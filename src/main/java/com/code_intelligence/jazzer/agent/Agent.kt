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

@file:JvmName("Agent")

package com.code_intelligence.jazzer.agent

import com.code_intelligence.jazzer.driver.Opt
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder
import com.code_intelligence.jazzer.instrumentor.Hooks
import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.sanitizers.Constants
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import com.code_intelligence.jazzer.utils.Log
import com.code_intelligence.jazzer.utils.ManifestUtils
import java.lang.instrument.Instrumentation
import java.nio.file.Paths
import kotlin.io.path.exists
import kotlin.io.path.isDirectory

fun install(instrumentation: Instrumentation) {
    installInternal(instrumentation)
}

fun installInternal(
    instrumentation: Instrumentation,
    instrumentOnly: List<String> = Opt.instrumentOnly.get(),
    userHookNames: List<String> = findManifestCustomHookNames() + Opt.customHooks.get(),
    disabledHookNames: List<String> = Opt.disabledHooks.get(),
    instrumentationIncludes: List<String> = Opt.instrumentationIncludes.get(),
    instrumentationExcludes: List<String> = Opt.instrumentationExcludes.get(),
    customHookIncludes: List<String> = Opt.customHookIncludes.get(),
    customHookExcludes: List<String> = Opt.customHookExcludes.get(),
    conditionalHooks: Boolean = Opt.conditionalHooks.get(),
    trace: List<String> = Opt.trace.get(),
    idSyncFile: String = Opt.idSyncFile.get(),
    dumpClassesDir: String = Opt.dumpClassesDir.get(),
    additionalClassesExcludes: List<String> = Opt.additionalClassesExcludes.get(),
) {
    val allCustomHookNames = (Constants.SANITIZER_HOOK_NAMES + userHookNames).toSet()
    check(allCustomHookNames.isNotEmpty()) { "No hooks registered; expected at least the built-in hooks" }
    val customHookNames = allCustomHookNames - disabledHookNames.toSet()
    val disabledCustomHooksToPrint = allCustomHookNames - customHookNames.toSet()
    if (disabledCustomHooksToPrint.isNotEmpty()) {
        Log.info("Not using the following disabled hooks: ${disabledCustomHooksToPrint.joinToString(", ")}")
    }

    val classNameGlobber = ClassNameGlobber(instrumentationIncludes, instrumentationExcludes + customHookNames)
    CoverageRecorder.classNameGlobber = classNameGlobber
    val customHookClassNameGlobber = ClassNameGlobber(customHookIncludes, customHookExcludes + customHookNames)
    // FIXME: Setting trace to the empty string explicitly results in all rather than no trace types
    //  being applied - this is unintuitive.
    val instrumentationTypes =
        (trace.takeIf { it.isNotEmpty() } ?: listOf("all"))
            .flatMap {
                when (it) {
                    "cmp" -> setOf(InstrumentationType.CMP)
                    "cov" -> setOf(InstrumentationType.COV)
                    "div" -> setOf(InstrumentationType.DIV)
                    "gep" -> setOf(InstrumentationType.GEP)
                    "indir" -> setOf(InstrumentationType.INDIR)
                    "native" -> setOf(InstrumentationType.NATIVE)
                    // Disable GEP instrumentation by default as it appears to negatively affect fuzzing
                    // performance. Our current GEP instrumentation only reports constant indices, but even
                    // when we instead reported non-constant indices, they tended to completely fill up the
                    // table of recent compares and value profile map.
                    "all" -> InstrumentationType.values().toSet() - InstrumentationType.GEP
                    else -> {
                        println("WARN: Skipping unknown instrumentation type $it")
                        emptySet()
                    }
                }
            }.toSet()

    val idSyncFilePath =
        idSyncFile.takeUnless { it.isEmpty() }?.let {
            Paths.get(it).also { path ->
                Log.info("Synchronizing coverage IDs in ${path.toAbsolutePath()}")
            }
        }
    val dumpClassesDirPath =
        dumpClassesDir.takeUnless { it.isEmpty() }?.let {
            Paths.get(it).toAbsolutePath().also { path ->
                if (path.exists() && path.isDirectory()) {
                    Log.info("Dumping instrumented classes into $path")
                } else {
                    Log.error("Cannot dump instrumented classes into $path; does not exist or not a directory")
                }
            }
        }
    val includedHookNames =
        instrumentationTypes
            .mapNotNull { type ->
                when (type) {
                    InstrumentationType.CMP -> "com.code_intelligence.jazzer.runtime.TraceCmpHooks"
                    InstrumentationType.DIV -> "com.code_intelligence.jazzer.runtime.TraceDivHooks"
                    InstrumentationType.INDIR -> "com.code_intelligence.jazzer.runtime.TraceIndirHooks"
                    InstrumentationType.NATIVE -> "com.code_intelligence.jazzer.runtime.NativeLibHooks"
                    else -> null
                }
            }
    val coverageIdSynchronizer =
        if (idSyncFilePath != null) {
            FileSyncCoverageIdStrategy(idSyncFilePath)
        } else {
            MemSyncCoverageIdStrategy()
        }

    // If we don't append the JARs containing the custom hooks to the bootstrap class loader,
    // third-party hooks not contained in the agent JAR will not be able to instrument Java standard
    // library classes. These classes are loaded by the bootstrap / system class loader and would
    // not be considered when resolving references to hook methods, leading to NoClassDefFoundError
    // being thrown.
    Hooks.appendHooksToBootstrapClassLoaderSearch(instrumentation, customHookNames.toSet())
    val (includedHooks, customHooks) = Hooks.loadHooks(additionalClassesExcludes, includedHookNames.toSet(), customHookNames.toSet())

    val runtimeInstrumentor =
        RuntimeInstrumentor(
            instrumentation,
            classNameGlobber,
            customHookClassNameGlobber,
            instrumentOnly.isNotEmpty(),
            instrumentationTypes,
            includedHooks.hooks,
            customHooks.hooks,
            conditionalHooks,
            customHooks.additionalHookClassNameGlobber,
            coverageIdSynchronizer,
            dumpClassesDirPath,
        )

    // These classes are e.g. dependencies of the RuntimeInstrumentor or hooks and thus were loaded
    // before the instrumentor was ready. Since we haven't enabled it yet, they can safely be
    // "retransformed": They haven't been transformed yet.
    val classesToRetransform =
        instrumentation.allLoadedClasses
            .filter {
                // Always exclude internal Jazzer classes from retransformation, as even attempting to
                // retransform those caused broken class definitions in older JVM versions. This points
                // to a JDK bug that was not backported.
                !it.name.startsWith("com.code_intelligence.jazzer.") &&
                    (
                        classNameGlobber.includes(it.name) ||
                            customHookClassNameGlobber.includes(it.name) ||
                            customHooks.additionalHookClassNameGlobber.includes(it.name)
                    )
            }.filter {
                instrumentation.isModifiableClass(it)
            }.toTypedArray()

    instrumentation.addTransformer(runtimeInstrumentor, true)

    if (classesToRetransform.isNotEmpty()) {
        if (instrumentation.isRetransformClassesSupported) {
            retransformClassesWithRetry(instrumentation, classesToRetransform)
        }
    }
}

private fun retransformClassesWithRetry(
    instrumentation: Instrumentation,
    classesToRetransform: Array<Class<*>>,
) {
    try {
        instrumentation.retransformClasses(*classesToRetransform)
    } catch (e: Throwable) {
        if (classesToRetransform.size == 1) {
            Log.warn("Error retransforming class ${classesToRetransform[0].name }", e)
        } else {
            // The docs state that no transformation was performed if an exception is thrown.
            // Try again in a binary search fashion, until the not transformable classes have been isolated and reported.
            retransformClassesWithRetry(instrumentation, classesToRetransform.copyOfRange(0, classesToRetransform.size / 2))
            retransformClassesWithRetry(
                instrumentation,
                classesToRetransform.copyOfRange(classesToRetransform.size / 2, classesToRetransform.size),
            )
        }
    }
}

private fun findManifestCustomHookNames() =
    ManifestUtils
        .combineManifestValues(ManifestUtils.HOOK_CLASSES)
        .flatMap { it.split(':') }
        .filter { it.isNotBlank() }
