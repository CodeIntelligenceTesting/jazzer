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

import com.code_intelligence.jazzer.instrumentor.InstrumentationType
import com.code_intelligence.jazzer.instrumentor.loadHooks
import com.code_intelligence.jazzer.runtime.ManifestUtils
import java.lang.instrument.Instrumentation
import java.nio.file.Path

val KNOWN_ARGUMENTS = listOf(
    "instrumentation_includes",
    "instrumentation_excludes",
    "custom_hook_includes",
    "custom_hook_excludes",
    "trace",
    "custom_hooks",
    "id_sync_file",
)

fun premain(agentArgs: String?, instrumentation: Instrumentation) {
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
                else -> splitArg[0] to splitArg[1].split(":")
            }
        }.toMap()
    val manifestCustomHookNames = ManifestUtils.combineManifestValues(ManifestUtils.HOOK_CLASSES).flatMap {
        it.split(':')
    }
    val customHookNames = manifestCustomHookNames + (argumentMap["custom_hooks"] ?: emptyList())
    val classNameGlobber = ClassNameGlobber(
        argumentMap["instrumentation_includes"] ?: emptyList(),
        (argumentMap["instrumentation_excludes"] ?: emptyList()) + customHookNames
    )
    val dependencyClassNameGlobber = ClassNameGlobber(
        argumentMap["custom_hook_includes"] ?: emptyList(),
        (argumentMap["custom_hook_excludes"] ?: emptyList()) + customHookNames
    )
    val instrumentationTypes = (argumentMap["trace"] ?: listOf("all")).flatMap {
        when (it) {
            "cmp" -> setOf(InstrumentationType.CMP)
            "cov" -> setOf(InstrumentationType.COV)
            "div" -> setOf(InstrumentationType.DIV)
            "gep" -> setOf(InstrumentationType.GEP)
            "all" -> InstrumentationType.values().toSet()
            else -> {
                println("WARN: Skipping unknown instrumentation type $it")
                emptySet()
            }
        }
    }.toSet()
    val idSyncFile = argumentMap["id_sync_file"]?.let {
        Path.of(it.single()).also { path ->
            println("INFO: Synchronizing coverage IDs in ${path.toAbsolutePath()}")
        }
    }

    val runtimeInstrumentor = RuntimeInstrumentor(classNameGlobber, dependencyClassNameGlobber, instrumentationTypes, idSyncFile)
    instrumentation.apply {
        addTransformer(runtimeInstrumentor)
    }

    val relevantClassesLoadedBeforeCustomHooks = instrumentation.allLoadedClasses
        .map { it.name }
        .filter { classNameGlobber.includes(it) || dependencyClassNameGlobber.includes(it) }
        .toSet()
    val customHooks = customHookNames.toSet().flatMap { hookClassName ->
        try {
            loadHooks(Class.forName(hookClassName)).also {
                println("INFO: Loaded ${it.size} hooks from $hookClassName")
            }
        } catch (_: ClassNotFoundException) {
            println("WARN: Failed to load hooks from $hookClassName")
            emptySet()
        }
    }
    val relevantClassesLoadedAfterCustomHooks = instrumentation.allLoadedClasses
        .map { it.name }
        .filter { classNameGlobber.includes(it) || dependencyClassNameGlobber.includes(it) }
        .toSet()
    val nonHookClassesLoadedByHooks = relevantClassesLoadedAfterCustomHooks - relevantClassesLoadedBeforeCustomHooks
    if (nonHookClassesLoadedByHooks.isNotEmpty()) {
        println("WARN: Hooks were not applied to the following classes as they are dependencies of hooks:")
        println("WARN: ${nonHookClassesLoadedByHooks.joinToString()}")
    }

    runtimeInstrumentor.registerCustomHooks(customHooks)
}
