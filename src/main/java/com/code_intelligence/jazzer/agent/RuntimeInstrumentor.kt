/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.agent

import com.code_intelligence.jazzer.instrumentor.ClassInstrumentor
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder
import com.code_intelligence.jazzer.instrumentor.Hook
import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import com.code_intelligence.jazzer.utils.Log
import io.github.classgraph.ClassGraph
import java.io.File
import java.lang.instrument.ClassFileTransformer
import java.lang.instrument.Instrumentation
import java.nio.file.Path
import java.security.ProtectionDomain
import kotlin.math.roundToInt
import kotlin.system.exitProcess
import kotlin.time.measureTimedValue

class RuntimeInstrumentor(
    private val instrumentation: Instrumentation,
    private val classesToFullyInstrument: ClassNameGlobber,
    private val classesToHookInstrument: ClassNameGlobber,
    private val instrumentOnly: Boolean,
    private val instrumentationTypes: Set<InstrumentationType>,
    private val includedHooks: List<Hook>,
    private val customHooks: List<Hook>,
    private var conditionalHooks: Boolean,
    // Dedicated name globber for additional classes to hook stated in hook annotations is needed due to
    // existing include and exclude pattern of classesToHookInstrument. All classes are included in hook
    // instrumentation except the ones from default excludes, like JDK and Kotlin classes. But additional
    // classes to hook, based on annotations, are allowed to reference normally ignored ones, like JDK
    // and Kotlin internals.
    // FIXME: Adding an additional class to hook will apply _all_ hooks to it and not only the one it's
    // defined in. At some point we might want to track the list of classes per custom hook rather than globally.
    private val additionalClassesToHookInstrument: ClassNameGlobber,
    private val coverageIdSynchronizer: CoverageIdStrategy,
    private val dumpClassesDir: Path?,
) : ClassFileTransformer {
    @kotlin.time.ExperimentalTime
    override fun transform(
        loader: ClassLoader?,
        internalClassName: String,
        classBeingRedefined: Class<*>?,
        protectionDomain: ProtectionDomain?,
        classfileBuffer: ByteArray,
    ): ByteArray? {
        var pathPrefix = ""
        // Throwables raised from transform are silently dropped, making it extremely hard to detect instrumentation
        // failures. The docs advise to use a top-level try-catch.
        // https://docs.oracle.com/javase/9/docs/api/java/lang/instrument/ClassFileTransformer.html
        return try {
            if (instrumentOnly && protectionDomain != null) {
                var outputPathPrefix =
                    protectionDomain
                        .getCodeSource()
                        .getLocation()
                        .getFile()
                        .toString()
                if (outputPathPrefix.isNotEmpty()) {
                    if (outputPathPrefix.contains(File.separator)) {
                        outputPathPrefix =
                            outputPathPrefix.substring(outputPathPrefix.lastIndexOf(File.separator) + 1, outputPathPrefix.length)
                    }

                    if (outputPathPrefix.endsWith(".jar")) {
                        outputPathPrefix = outputPathPrefix.substring(0, outputPathPrefix.lastIndexOf(".jar"))
                    }

                    if (outputPathPrefix.isNotEmpty()) {
                        pathPrefix = outputPathPrefix + File.separator
                    }
                }
            }

            // Bail out early if we would instrument ourselves. This prevents ClassCircularityErrors as we might need to
            // load additional Jazzer classes until we reach the full exclusion logic.
            if (internalClassName.startsWith("com/code_intelligence/jazzer/")) {
                return null
            }
            // Workaround for a JDK bug (http://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8299798):
            // When retransforming a class in the Java standard library, the provided classfileBuffer does not contain
            // any StackMapTable attributes. Our transformations require stack map frames to calculate the number of
            // local variables and stack slots as well as when adding control flow.
            //
            // We work around this by reloading the class file contents if we are retransforming (classBeingRedefined
            // is also non-null in this situation) and the class is provided by the bootstrap loader.
            //
            // Alternatives considered:
            // Using ClassWriter.COMPUTE_FRAMES as an escape hatch isn't possible in the context of an agent as the
            // computation may itself need to load classes, which leads to circular loads and incompatible class
            // redefinitions.
            transformInternal(internalClassName, classfileBuffer.takeUnless { loader == null && classBeingRedefined != null })
        } catch (t: Throwable) {
            if (dumpClassesDir != null) {
                dumpToClassFile(internalClassName, classfileBuffer, basenameSuffix = ".failed", pathPrefix = pathPrefix)
            }
            Log.warn("Failed to instrument $internalClassName:", t)
            throw t
        }.also { instrumentedByteCode ->
            // Only dump classes that were instrumented.
            if (instrumentedByteCode != null && dumpClassesDir != null) {
                dumpToClassFile(internalClassName, instrumentedByteCode, pathPrefix = pathPrefix)
                dumpToClassFile(internalClassName, classfileBuffer, basenameSuffix = ".original", pathPrefix = pathPrefix)
            }
        }
    }

    private fun dumpToClassFile(
        internalClassName: String,
        bytecode: ByteArray,
        basenameSuffix: String = "",
        pathPrefix: String = "",
    ) {
        val relativePath = "$pathPrefix$internalClassName$basenameSuffix.class"
        val absolutePath = dumpClassesDir!!.resolve(relativePath)
        val dumpFile = absolutePath.toFile()
        dumpFile.parentFile.mkdirs()
        dumpFile.writeBytes(bytecode)
    }

    @kotlin.time.ExperimentalTime
    override fun transform(
        module: Module?,
        loader: ClassLoader?,
        internalClassName: String,
        classBeingRedefined: Class<*>?,
        protectionDomain: ProtectionDomain?,
        classfileBuffer: ByteArray,
    ): ByteArray? {
        try {
            if (module != null && !module.canRead(RuntimeInstrumentor::class.java.module)) {
                // Make all other modules read our (unnamed) module, which allows them to access the classes needed by the
                // instrumentations, e.g. CoverageMap. If a module can't be modified, it should not be instrumented as the
                // injected bytecode might throw NoClassDefFoundError.
                // https://mail.openjdk.java.net/pipermail/jigsaw-dev/2021-May/014663.html
                if (!instrumentation.isModifiableModule(module)) {
                    val prettyClassName = internalClassName.replace('/', '.')
                    Log.warn("Failed to instrument $prettyClassName in unmodifiable module ${module.name}, skipping")
                    return null
                }
                instrumentation.redefineModule(
                    module,
                    setOf(RuntimeInstrumentor::class.java.module), // extraReads
                    emptyMap(),
                    emptyMap(),
                    emptySet(),
                    emptyMap(),
                )
            }
        } catch (t: Throwable) {
            // Throwables raised from transform are silently dropped, making it extremely hard to detect instrumentation
            // failures. The docs advise to use a top-level try-catch.
            // https://docs.oracle.com/javase/9/docs/api/java/lang/instrument/ClassFileTransformer.html
            if (dumpClassesDir != null) {
                dumpToClassFile(internalClassName, classfileBuffer, basenameSuffix = ".failed")
            }
            Log.warn("Failed to instrument $internalClassName:", t)
            throw t
        }
        return transform(loader, internalClassName, classBeingRedefined, protectionDomain, classfileBuffer)
    }

    @kotlin.time.ExperimentalTime
    fun transformInternal(
        internalClassName: String,
        maybeClassfileBuffer: ByteArray?,
    ): ByteArray? {
        val (fullInstrumentation, printInfo) =
            when {
                classesToFullyInstrument.includes(internalClassName) -> Pair(true, true)
                classesToHookInstrument.includes(internalClassName) -> Pair(false, true)
                // The classes to hook specified by hooks are more of an implementation detail of the hook. The list is
                // always the same unless the set of hooks changes and doesn't help the user judge whether their classes are
                // being instrumented, so we don't print info for them.
                additionalClassesToHookInstrument.includes(internalClassName) -> Pair(false, false)
                else -> return null
            }
        val className = internalClassName.replace('/', '.')
        val classfileBuffer =
            maybeClassfileBuffer ?: ClassGraph()
                .enableSystemJarsAndModules()
                .acceptLibOrExtJars()
                .ignoreClassVisibility()
                .acceptClasses(className)
                .scan()
                .use {
                    it.getClassInfo(className)?.resource?.load() ?: run {
                        Log.warn("Failed to load bytecode of class $className")
                        return null
                    }
                }
        val (instrumentedBytecode, duration) =
            measureTimedValue {
                try {
                    instrument(internalClassName, classfileBuffer, fullInstrumentation)
                } catch (e: CoverageIdException) {
                    Log.error("Coverage IDs are out of sync")
                    e.printStackTrace()
                    exitProcess(1)
                }
            }
        val durationInMs = duration.inWholeMilliseconds
        val sizeIncrease = ((100.0 * (instrumentedBytecode.size - classfileBuffer.size)) / classfileBuffer.size).roundToInt()
        if (printInfo) {
            if (fullInstrumentation) {
                Log.info("Instrumented $className (took $durationInMs ms, size +$sizeIncrease%)")
            } else {
                Log.info("Instrumented $className with custom hooks only (took $durationInMs ms, size +$sizeIncrease%)")
            }
        }
        return instrumentedBytecode
    }

    private fun instrument(
        internalClassName: String,
        bytecode: ByteArray,
        fullInstrumentation: Boolean,
    ): ByteArray {
        val classWithHooksEnabledField =
            if (conditionalHooks) {
                // Let the hook instrumentation emit additional logic that checks the value of the
                // hooksEnabled field on this class and skips the hook if it is false.
                "com/code_intelligence/jazzer/runtime/JazzerInternal"
            } else {
                null
            }
        return ClassInstrumentor(internalClassName, bytecode).run {
            if (fullInstrumentation) {
                // Coverage instrumentation must be performed before any other code updates
                // or there will be additional coverage points injected if any calls are inserted
                // and JaCoCo will produce a broken coverage report.
                coverageIdSynchronizer.withIdForClass(internalClassName) { firstId ->
                    coverage(firstId).also { actualNumEdgeIds ->
                        CoverageRecorder.recordInstrumentedClass(
                            internalClassName,
                            bytecode,
                            firstId,
                            actualNumEdgeIds,
                        )
                    }
                }
                // Hook instrumentation must be performed after data flow tracing as the injected
                // bytecode would trigger the GEP callbacks for byte[].
                traceDataFlow(instrumentationTypes)
                hooks(includedHooks + customHooks, classWithHooksEnabledField)
            } else {
                hooks(customHooks, classWithHooksEnabledField)
            }
            instrumentedBytecode
        }
    }
}
