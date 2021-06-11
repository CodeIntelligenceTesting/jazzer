// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.agent

import com.code_intelligence.jazzer.instrumentor.ClassInstrumentor
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder
import com.code_intelligence.jazzer.instrumentor.Hook
import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.instrumentor.loadHooks
import com.code_intelligence.jazzer.runtime.NativeLibHooks
import com.code_intelligence.jazzer.runtime.TraceCmpHooks
import com.code_intelligence.jazzer.runtime.TraceDivHooks
import com.code_intelligence.jazzer.runtime.TraceIndirHooks
import java.lang.IllegalArgumentException
import java.lang.instrument.ClassFileTransformer
import java.lang.instrument.Instrumentation
import java.nio.file.Path
import java.security.ProtectionDomain
import kotlin.math.roundToInt
import kotlin.system.exitProcess
import kotlin.time.measureTimedValue

private val BASE_INCLUDED_CLASS_NAME_GLOBS = listOf(
    "**", // everything
)

private val BASE_EXCLUDED_CLASS_NAME_GLOBS = listOf(
    "\\[**", // array types
    "com.code_intelligence.jazzer.**",
    "com.sun.**", // package for Proxy objects
    "java.**",
    "jaz.Ter", // safe companion of the honeypot class used by sanitizers
    "jaz.Zer", // honeypot class used by sanitizers
    "jdk.**",
    "kotlin.**",
    "sun.**",
)

class SimpleGlobMatcher(val glob: String) {
    private enum class Type {
        // foo.bar (matches foo.bar only)
        FULL_MATCH,
        // foo.** (matches foo.bar and foo.bar.baz)
        PATH_WILDCARD_SUFFIX,
        // foo.* (matches foo.bar, but not foo.bar.baz)
        SEGMENT_WILDCARD_SUFFIX,
    }

    private val type: Type
    private val prefix: String

    init {
        // Remain compatible with globs such as "\\[" that use escaping.
        val pattern = glob.replace("\\", "")
        when {
            !pattern.contains('*') -> {
                type = Type.FULL_MATCH
                prefix = pattern
            }
            // Ends with "**" and contains no other '*'.
            pattern.endsWith("**") && pattern.indexOf('*') == pattern.length - 2 -> {
                type = Type.PATH_WILDCARD_SUFFIX
                prefix = pattern.removeSuffix("**")
            }
            // Ends with "*" and contains no other '*'.
            pattern.endsWith('*') && pattern.indexOf('*') == pattern.length - 1 -> {
                type = Type.SEGMENT_WILDCARD_SUFFIX
                prefix = pattern.removeSuffix("*")
            }
            else -> throw IllegalArgumentException(
                "Unsupported glob pattern (only foo.bar, foo.* and foo.** are supported): $pattern"
            )
        }
    }

    /**
     * Checks whether [maybeInternalClassName], which may be internal (foo/bar) or not (foo.bar), matches [glob].
     */
    fun matches(maybeInternalClassName: String): Boolean {
        val className = maybeInternalClassName.replace('/', '.')
        return when (type) {
            Type.FULL_MATCH -> className == prefix
            Type.PATH_WILDCARD_SUFFIX -> className.startsWith(prefix)
            Type.SEGMENT_WILDCARD_SUFFIX -> {
                // className starts with prefix and contains no further '.'.
                className.startsWith(prefix) &&
                    className.indexOf('.', startIndex = prefix.length) == -1
            }
        }
    }
}

internal class ClassNameGlobber(includes: List<String>, excludes: List<String>) {
    // If no include globs are provided, start with all classes.
    private val includeMatchers = (if (includes.isEmpty()) BASE_INCLUDED_CLASS_NAME_GLOBS else includes)
        .map(::SimpleGlobMatcher)

    // If no include globs are provided, additionally exclude stdlib classes as well as our own classes.
    private val excludeMatchers = (if (includes.isEmpty()) BASE_EXCLUDED_CLASS_NAME_GLOBS + excludes else excludes)
        .map(::SimpleGlobMatcher)

    fun includes(className: String): Boolean {
        return includeMatchers.any { it.matches(className) } && excludeMatchers.none { it.matches(className) }
    }
}

internal class RuntimeInstrumentor(
    private val instrumentation: Instrumentation,
    private val classesToInstrument: ClassNameGlobber,
    private val dependencyClassesToInstrument: ClassNameGlobber,
    private val instrumentationTypes: Set<InstrumentationType>,
    idSyncFile: Path?,
    private val dumpClassesDir: Path?,
) : ClassFileTransformer {

    private val coverageIdSynchronizer = if (idSyncFile != null)
        SynchronizedCoverageIdStrategy(idSyncFile)
    else
        TrivialCoverageIdStrategy()

    private val includedHooks = instrumentationTypes
        .mapNotNull { type ->
            when (type) {
                InstrumentationType.CMP -> TraceCmpHooks::class.java
                InstrumentationType.DIV -> TraceDivHooks::class.java
                InstrumentationType.INDIR -> TraceIndirHooks::class.java
                InstrumentationType.NATIVE -> NativeLibHooks::class.java
                else -> null
            }
        }
        .flatMap { loadHooks(it) }
    private val customHooks = emptyList<Hook>().toMutableList()

    fun registerCustomHooks(hooks: List<Hook>) {
        customHooks.addAll(hooks)
    }

    @OptIn(kotlin.time.ExperimentalTime::class)
    override fun transform(
        loader: ClassLoader?,
        internalClassName: String,
        classBeingRedefined: Class<*>?,
        protectionDomain: ProtectionDomain?,
        classfileBuffer: ByteArray,
    ): ByteArray? {
        return try {
            // Bail out early if we would instrument ourselves. This prevents ClassCircularityErrors as we might need to
            // load additional Jazzer classes until we reach the full exclusion logic.
            if (internalClassName.startsWith("com/code_intelligence/jazzer/"))
                return null
            transformInternal(internalClassName, classfileBuffer)
        } catch (t: Throwable) {
            // Throwables raised from transform are silently dropped, making it extremely hard to detect instrumentation
            // failures. The docs advise to use a top-level try-catch.
            // https://docs.oracle.com/javase/9/docs/api/java/lang/instrument/ClassFileTransformer.html
            t.printStackTrace()
            throw t
        }.also { instrumentedByteCode ->
            // Only dump classes that were instrumented.
            if (instrumentedByteCode != null && dumpClassesDir != null) {
                val relativePath = "$internalClassName.class"
                val absolutePath = dumpClassesDir.resolve(relativePath)
                val dumpFile = absolutePath.toFile()
                dumpFile.parentFile.mkdirs()
                dumpFile.writeBytes(instrumentedByteCode)
            }
        }
    }

    override fun transform(
        module: Module?,
        loader: ClassLoader?,
        internalClassName: String,
        classBeingRedefined: Class<*>?,
        protectionDomain: ProtectionDomain?,
        classfileBuffer: ByteArray
    ): ByteArray? {
        if (module != null && !module.canRead(RuntimeInstrumentor::class.java.module)) {
            // Make all other modules read our (unnamed) module, which allows them to access the classes needed by the
            // instrumentations, e.g. CoverageMap. If a module can't be modified, it should not be instrumented as the
            // injected bytecode might throw NoClassDefFoundError.
            // https://mail.openjdk.java.net/pipermail/jigsaw-dev/2021-May/014663.html
            if (!instrumentation.isModifiableModule(module)) {
                val prettyClassName = internalClassName.replace('/', '.')
                println("WARN: Failed to instrument $prettyClassName in unmodifiable module ${module.name}, skipping")
                return null
            }
            instrumentation.redefineModule(
                module,
                /* extraReads */ setOf(RuntimeInstrumentor::class.java.module),
                emptyMap(),
                emptyMap(),
                emptySet(),
                emptyMap()
            )
        }
        return transform(loader, internalClassName, classBeingRedefined, protectionDomain, classfileBuffer)
    }

    @OptIn(kotlin.time.ExperimentalTime::class)
    fun transformInternal(internalClassName: String, classfileBuffer: ByteArray): ByteArray? {
        val fullInstrumentation = when {
            classesToInstrument.includes(internalClassName) -> true
            dependencyClassesToInstrument.includes(internalClassName) -> false
            else -> return null
        }
        val prettyClassName = internalClassName.replace('/', '.')
        val (instrumentedBytecode, duration) = measureTimedValue {
            try {
                instrument(internalClassName, classfileBuffer, fullInstrumentation)
            } catch (e: CoverageIdException) {
                println("ERROR: Coverage IDs are out of sync")
                e.printStackTrace()
                exitProcess(1)
            } catch (e: Exception) {
                println("WARN: Failed to instrument $prettyClassName, skipping")
                e.printStackTrace()
                return null
            }
        }
        val durationInMs = duration.inMilliseconds.roundToInt()
        val sizeIncrease = ((100.0 * (instrumentedBytecode.size - classfileBuffer.size)) / classfileBuffer.size).roundToInt()
        if (fullInstrumentation) {
            println("INFO: Instrumented $prettyClassName (took $durationInMs ms, size +$sizeIncrease%)")
        } else {
            println("INFO: Instrumented $prettyClassName with custom hooks only (took $durationInMs ms, size +$sizeIncrease%)")
        }
        return instrumentedBytecode
    }

    private fun instrument(internalClassName: String, bytecode: ByteArray, fullInstrumentation: Boolean): ByteArray {
        return ClassInstrumentor(bytecode).run {
            if (fullInstrumentation) {
                // Hook instrumentation must be performed after data flow tracing as the injected
                // bytecode would trigger the GEP callbacks for byte[]. Coverage instrumentation
                // must be performed after hook instrumentation as the injected bytecode would
                // trigger the GEP callbacks for ByteBuffer.
                traceDataFlow(instrumentationTypes)
                hooks(includedHooks + customHooks)
                val firstId = coverageIdSynchronizer.obtainFirstId(internalClassName)
                var actualNumEdgeIds = 0
                try {
                    actualNumEdgeIds = coverage(firstId)
                } finally {
                    coverageIdSynchronizer.commitIdCount(actualNumEdgeIds)
                }
                CoverageRecorder.recordInstrumentedClass(internalClassName, bytecode, firstId, firstId + actualNumEdgeIds)
            } else {
                hooks(customHooks)
            }
            instrumentedBytecode
        }
    }
}
