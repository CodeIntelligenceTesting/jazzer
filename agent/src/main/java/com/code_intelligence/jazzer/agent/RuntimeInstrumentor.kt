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
import com.code_intelligence.jazzer.instrumentor.Hook
import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.instrumentor.loadHooks
import com.code_intelligence.jazzer.runtime.TraceCmpHooks
import com.code_intelligence.jazzer.runtime.TraceDivHooks
import java.lang.instrument.ClassFileTransformer
import java.nio.file.FileSystems
import java.nio.file.Path
import java.security.ProtectionDomain
import kotlin.math.roundToInt
import kotlin.time.measureTimedValue

private val BASE_INCLUDED_CLASS_NAME_GLOBS = listOf(
    "**", // everything
)

private val BASE_EXCLUDED_CLASS_NAME_GLOBS = listOf(
    "\\[**", // array types
    "com.code_intelligence.jazzer.**",
    "com.sun.**", // package for Proxy objects
    "java.**",
    "jdk.**",
    "kotlin.**",
    "org.objectweb.asm.**", // dependency used for bytecode manipulation
    "sun.**",
)

private fun packageGlobToMatcher(glob: String) =
    FileSystems.getDefault().getPathMatcher("glob:${glob.replace('.', '/')}")

internal class ClassNameGlobber(includes: List<String>, excludes: List<String>) {
    // If no include globs are provided, start with all classes.
    private val includeMatchers = (if (includes.isEmpty()) BASE_INCLUDED_CLASS_NAME_GLOBS else includes)
        .map(::packageGlobToMatcher)

    // If no include globs are provided, additionally exclude stdlib classes as well as our own classes.
    private val excludeMatchers = (if (includes.isEmpty()) BASE_EXCLUDED_CLASS_NAME_GLOBS + excludes else excludes)
        .map(::packageGlobToMatcher)

    fun includes(className: String): Boolean {
        val internalClassNameAsPath = Path.of(className.replace('.', '/'))
        return includeMatchers.any { it.matches(internalClassNameAsPath) } &&
            excludeMatchers.none { it.matches(internalClassNameAsPath) }
    }
}

internal class RuntimeInstrumentor(
    private val classesToInstrument: ClassNameGlobber,
    private val dependencyClassesToInstrument: ClassNameGlobber,
    private val instrumentationTypes: Set<InstrumentationType>
) : ClassFileTransformer {

    private val includedHooks = instrumentationTypes
        .mapNotNull { type ->
            when (type) {
                InstrumentationType.CMP -> TraceCmpHooks::class.java
                InstrumentationType.DIV -> TraceDivHooks::class.java
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
        loader: ClassLoader,
        internalClassName: String,
        classBeingRedefined: Class<*>?,
        protectionDomain: ProtectionDomain?,
        classfileBuffer: ByteArray,
    ): ByteArray? {
        val fullInstrumentation = when {
            classesToInstrument.includes(internalClassName) -> true
            dependencyClassesToInstrument.includes(internalClassName) -> false
            else -> return null
        }
        val prettyClassName = internalClassName.replace('/', '.')
        val (instrumentedBytecode, duration) = measureTimedValue {
            try {
                instrument(classfileBuffer, fullInstrumentation)
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

    private fun instrument(bytecode: ByteArray, fullInstrumentation: Boolean): ByteArray {
        return ClassInstrumentor(bytecode).run {
            if (fullInstrumentation) {
                // Hook instrumentation must be performed after data flow tracing as the injected
                // bytecode would trigger the GEP callbacks for byte[]. Coverage instrumentation
                // must be performed after hook instrumentation as the injected bytecode would
                // trigger the GEP callbacks for ByteBuffer.
                traceDataFlow(instrumentationTypes)
                hooks(includedHooks + customHooks)
                coverage()
            } else {
                hooks(customHooks)
            }
            instrumentedBytecode
        }
    }
}
