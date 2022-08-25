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

@file:JvmName("Agent")

package com.code_intelligence.jazzer.agent

import com.code_intelligence.jazzer.driver.Opt
import com.code_intelligence.jazzer.instrumentor.CoverageRecorder
import com.code_intelligence.jazzer.instrumentor.Hooks
import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import com.code_intelligence.jazzer.utils.ManifestUtils
import java.lang.instrument.Instrumentation
import java.nio.file.Paths
import kotlin.io.path.exists
import kotlin.io.path.isDirectory

fun install(instrumentation: Instrumentation) {
    val manifestCustomHookNames =
        ManifestUtils.combineManifestValues(ManifestUtils.HOOK_CLASSES).flatMap {
            it.split(':')
        }.filter { it.isNotBlank() }
    val allCustomHookNames = (manifestCustomHookNames + Opt.customHooks).toSet()
    val disabledCustomHookNames = Opt.disabledHooks.toSet()
    val customHookNames = allCustomHookNames - disabledCustomHookNames
    val disabledCustomHooksToPrint = allCustomHookNames - customHookNames.toSet()
    if (disabledCustomHooksToPrint.isNotEmpty()) {
        println("INFO: Not using the following disabled hooks: ${disabledCustomHooksToPrint.joinToString(", ")}")
    }

    val classNameGlobber = ClassNameGlobber(Opt.instrumentationIncludes, Opt.instrumentationExcludes + customHookNames)
    CoverageRecorder.classNameGlobber = classNameGlobber
    val customHookClassNameGlobber = ClassNameGlobber(Opt.customHookIncludes, Opt.customHookExcludes + customHookNames)
    // FIXME: Setting trace to the empty string explicitly results in all rather than no trace types
    //  being applied - this is unintuitive.
    val instrumentationTypes = (Opt.trace.takeIf { it.isNotEmpty() } ?: listOf("all")).flatMap {
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
    val idSyncFile = Opt.idSyncFile?.takeUnless { it.isEmpty() }?.let {
        Paths.get(it).also { path ->
            println("INFO: Synchronizing coverage IDs in ${path.toAbsolutePath()}")
        }
    }
    val dumpClassesDir = Opt.dumpClassesDir.takeUnless { it.isEmpty() }?.let {
        Paths.get(it).toAbsolutePath().also { path ->
            if (path.exists() && path.isDirectory()) {
                println("INFO: Dumping instrumented classes into $path")
            } else {
                println("ERROR: Cannot dump instrumented classes into $path; does not exist or not a directory")
            }
        }
    }
    val includedHookNames = instrumentationTypes
        .mapNotNull { type ->
            when (type) {
                InstrumentationType.CMP -> "com.code_intelligence.jazzer.runtime.TraceCmpHooks"
                InstrumentationType.DIV -> "com.code_intelligence.jazzer.runtime.TraceDivHooks"
                InstrumentationType.INDIR -> "com.code_intelligence.jazzer.runtime.TraceIndirHooks"
                InstrumentationType.NATIVE -> "com.code_intelligence.jazzer.runtime.NativeLibHooks"
                else -> null
            }
        }
    val coverageIdSynchronizer = if (idSyncFile != null)
        FileSyncCoverageIdStrategy(idSyncFile)
    else
        MemSyncCoverageIdStrategy()

    // If we don't append the JARs containing the custom hooks to the bootstrap class loader,
    // third-party hooks not contained in the agent JAR will not be able to instrument Java standard
    // library classes. These classes are loaded by the bootstrap / system class loader and would
    // not be considered when resolving references to hook methods, leading to NoClassDefFoundError
    // being thrown.
    Hooks.appendHooksToBootstrapClassLoaderSearch(instrumentation, customHookNames.toSet())
    val (includedHooks, customHooks) = Hooks.loadHooks(includedHookNames.toSet(), customHookNames.toSet())

    val runtimeInstrumentor = RuntimeInstrumentor(
        instrumentation,
        classNameGlobber,
        customHookClassNameGlobber,
        instrumentationTypes,
        includedHooks.hooks,
        customHooks.hooks,
        customHooks.additionalHookClassNameGlobber,
        coverageIdSynchronizer,
        dumpClassesDir,
    )

    // These classes are e.g. dependencies of the RuntimeInstrumentor or hooks and thus were loaded
    // before the instrumentor was ready. Since we haven't enabled it yet, they can safely be
    // "retransformed": They haven't been transformed yet.
    val classesToRetransform = instrumentation.allLoadedClasses
        .filter {
            classNameGlobber.includes(it.name) ||
                customHookClassNameGlobber.includes(it.name) ||
                customHooks.additionalHookClassNameGlobber.includes(it.name)
        }
        .filter {
            instrumentation.isModifiableClass(it)
        }
        .toTypedArray()

    instrumentation.addTransformer(runtimeInstrumentor, true)

    if (classesToRetransform.isNotEmpty()) {
        if (instrumentation.isRetransformClassesSupported) {
            instrumentation.retransformClasses(*classesToRetransform)
        } else {
            println("WARN: Instrumentation was not applied to the following classes as they are dependencies of hooks:")
            println("WARN: ${classesToRetransform.joinToString()}")
        }
    }
}
