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

import com.code_intelligence.jazzer.instrumentor.CoverageRecorder
import com.code_intelligence.jazzer.instrumentor.Hooks
import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.runtime.ManifestUtils
import com.code_intelligence.jazzer.runtime.NativeLibHooks
import com.code_intelligence.jazzer.runtime.SignalHandler
import com.code_intelligence.jazzer.runtime.TraceCmpHooks
import com.code_intelligence.jazzer.runtime.TraceDivHooks
import com.code_intelligence.jazzer.runtime.TraceIndirHooks
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import java.io.File
import java.lang.instrument.Instrumentation
import java.net.URI
import java.nio.file.Paths
import java.util.jar.JarFile
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.exists
import kotlin.io.path.isDirectory

private val KNOWN_ARGUMENTS = listOf(
    "instrumentation_includes",
    "instrumentation_excludes",
    "custom_hook_includes",
    "custom_hook_excludes",
    "trace",
    "custom_hooks",
    "id_sync_file",
    "dump_classes_dir",
)

// To be accessible by the agent classes the native library has to be loaded by the same class loader.
// premain is executed in the context of the system class loader. At the beginning of premain the agent jar is added to
// the bootstrap class loader and all subsequently required agent classes are loaded by it. Hence, it's not possible to
// load the native library directly in premain by the system class loader, instead it's delegated to NativeLibraryLoader
// loaded by the bootstrap class loader.
internal object NativeLibraryLoader {
    fun load() {
        // Calls JNI_OnLoad_jazzer_initialize in the driver, which ensures that dynamically
        // linked JNI methods are resolved against it.
        System.loadLibrary("jazzer_initialize")
    }
}

private object AgentJarFinder {
    val agentJarFile = jarUriForClass(AgentJarFinder::class.java)?.let { JarFile(File(it)) }
}

fun jarUriForClass(clazz: Class<*>): URI? {
    return clazz.protectionDomain?.codeSource?.location?.toURI()
}

private val argumentDelimiter =
    if (System.getProperty("os.name").startsWith("Windows")) ";" else ":"

@OptIn(ExperimentalPathApi::class)
fun premain(agentArgs: String?, instrumentation: Instrumentation) {
    // Add the agent jar (i.e., the jar out of which we are currently executing) to the search path of the bootstrap
    // class loader to ensure that instrumented classes can find the CoverageMap class regardless of which ClassLoader
    // they are using.
    if (AgentJarFinder.agentJarFile != null) {
        instrumentation.appendToBootstrapClassLoaderSearch(AgentJarFinder.agentJarFile)
    } else {
        println("WARN: Failed to add agent JAR to bootstrap class loader search path")
    }
    NativeLibraryLoader.load()

    val argumentMap = (agentArgs ?: "")
        .split(',')
        .mapNotNull {
            val splitArg = it.split('=', limit = 2)
            when {
                splitArg.size != 2 -> {
                    if (splitArg[0].isNotEmpty())
                        println("WARN: Ignoring argument ${splitArg[0]} without value")
                    null
                }
                splitArg[0] !in KNOWN_ARGUMENTS -> {
                    println("WARN: Ignoring unknown argument ${splitArg[0]}")
                    null
                }
                else -> splitArg[0] to splitArg[1].split(argumentDelimiter)
            }
        }.toMap()
    val manifestCustomHookNames =
        ManifestUtils.combineManifestValues(ManifestUtils.HOOK_CLASSES).flatMap {
            it.split(':')
        }.filter { it.isNotBlank() }
    val customHookNames = manifestCustomHookNames + (argumentMap["custom_hooks"] ?: emptyList())
    val classNameGlobber = ClassNameGlobber(
        argumentMap["instrumentation_includes"] ?: emptyList(),
        (argumentMap["instrumentation_excludes"] ?: emptyList()) + customHookNames
    )
    CoverageRecorder.classNameGlobber = classNameGlobber
    val customHookClassNameGlobber = ClassNameGlobber(
        argumentMap["custom_hook_includes"] ?: emptyList(),
        (argumentMap["custom_hook_excludes"] ?: emptyList()) + customHookNames
    )
    val instrumentationTypes = (argumentMap["trace"] ?: listOf("all")).flatMap {
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
    val idSyncFile = argumentMap["id_sync_file"]?.let {
        Paths.get(it.single()).also { path ->
            println("INFO: Synchronizing coverage IDs in ${path.toAbsolutePath()}")
        }
    }
    val dumpClassesDir = argumentMap["dump_classes_dir"]?.let {
        Paths.get(it.single()).toAbsolutePath().also { path ->
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
                InstrumentationType.CMP -> TraceCmpHooks::class.java.name
                InstrumentationType.DIV -> TraceDivHooks::class.java.name
                InstrumentationType.INDIR -> TraceIndirHooks::class.java.name
                InstrumentationType.NATIVE -> NativeLibHooks::class.java.name
                else -> null
            }
        }
    val coverageIdSynchronizer = if (idSyncFile != null)
        FileSyncCoverageIdStrategy(idSyncFile)
    else
        MemSyncCoverageIdStrategy()

    val classesToHookBeforeLoadingCustomHooks = instrumentation.allLoadedClasses
        .map { it.name }
        .filter { customHookClassNameGlobber.includes(it) }
        .toSet()

    val (includedHooks, customHooks) = Hooks.loadHooks(includedHookNames.toSet(), customHookNames.toSet())
    // If we don't append the JARs containing the custom hooks to the bootstrap class loader,
    // third-party hooks not contained in the agent JAR will not be able to instrument Java standard
    // library classes. These classes are loaded by the bootstrap / system class loader and would
    // not be considered when resolving references to hook methods, leading to NoClassDefFoundError
    // being thrown.
    customHooks.hookClasses
        .mapNotNull { jarUriForClass(it) }
        .toSet()
        .map { JarFile(File(it)) }
        .forEach { instrumentation.appendToBootstrapClassLoaderSearch(it) }

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
    instrumentation.addTransformer(runtimeInstrumentor, true)

    val classesToHookAfterLoadingCustomHooks = instrumentation.allLoadedClasses
        .map { it.name }
        .filter {
            customHookClassNameGlobber.includes(it) ||
                customHooks.additionalHookClassNameGlobber.includes(it)
        }
        .toSet()
    val classesMissingHooks =
        (classesToHookAfterLoadingCustomHooks - classesToHookBeforeLoadingCustomHooks).toMutableSet()
    if (classesMissingHooks.isNotEmpty()) {
        if (instrumentation.isRetransformClassesSupported) {
            // Only retransform classes that are not subject to coverage instrumentation since
            // our coverage instrumentation does not support retransformation yet.
            val classesToHook = classesMissingHooks
                .filter { !classNameGlobber.includes(it) }
                .map { Class.forName(it) }
                .toTypedArray()
            if (classesToHook.isNotEmpty()) {
                instrumentation.retransformClasses(*classesToHook)
            }
            classesMissingHooks -= classesToHook.map { it.name }.toSet()
        }
        if (classesMissingHooks.isNotEmpty()) {
            println("WARN: Hooks were not applied to the following classes as they are dependencies of hooks:")
            println("WARN: ${classesMissingHooks.joinToString()}")
        }
    }

    SignalHandler.initialize()
}
