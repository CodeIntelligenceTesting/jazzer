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
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import java.lang.instrument.ClassFileTransformer
import java.lang.instrument.Instrumentation
import java.nio.file.Path
import java.security.ProtectionDomain
import kotlin.math.roundToInt
import kotlin.system.exitProcess
import kotlin.time.measureTimedValue

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
                System.err.println("ERROR: Coverage IDs are out of sync")
                e.printStackTrace()
                exitProcess(1)
            } catch (e: Exception) {
                println("WARN: Failed to instrument $prettyClassName, skipping")
                e.printStackTrace()
                return null
            }
        }
        val durationInMs = duration.inWholeMilliseconds
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
