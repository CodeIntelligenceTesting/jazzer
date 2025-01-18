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

package com.code_intelligence.jazzer.instrumentor

import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import com.code_intelligence.jazzer.utils.ClassNameGlobber
import com.code_intelligence.jazzer.utils.Log
import io.github.classgraph.ClassGraph
import io.github.classgraph.ScanResult
import java.lang.instrument.Instrumentation
import java.lang.reflect.Method
import java.util.jar.JarFile

data class Hooks(
    val hooks: List<Hook>,
    val hookClasses: Set<Class<*>>,
    val additionalHookClassNameGlobber: ClassNameGlobber,
) {
    companion object {
        fun appendHooksToBootstrapClassLoaderSearch(
            instrumentation: Instrumentation,
            hookClassNames: Set<String>,
        ) {
            hookClassNames
                .mapNotNull { hook ->
                    val hookClassFilePath = "/${hook.replace('.', '/')}.class"
                    val hookClassFile = Companion::class.java.getResource(hookClassFilePath) ?: return@mapNotNull null
                    if ("jar" != hookClassFile.protocol) {
                        return@mapNotNull null
                    }
                    // hookClassFile.file looks as follows:
                    // file:/tmp/ExampleFuzzerHooks_deploy.jar!/com/example/ExampleFuzzerHooks.class
                    hookClassFile.file.removePrefix("file:").takeWhile { it != '!' }
                }.toSet()
                .map { JarFile(it) }
                .forEach { instrumentation.appendToBootstrapClassLoaderSearch(it) }
        }

        fun loadHooks(
            excludeHookClassNames: List<String>,
            vararg hookClassNames: Set<String>,
        ): List<Hooks> =
            ClassGraph()
                .enableClassInfo()
                .enableSystemJarsAndModules()
                .acceptLibOrExtJars()
                .rejectPackages("jaz.*", "com.code_intelligence.jazzer.*")
                .scan()
                .use { scanResult ->
                    // Capture scanResult in HooksLoader field to not pass it through
                    // all internal hook loading methods.
                    val loader = HooksLoader(scanResult, excludeHookClassNames)
                    hookClassNames.map(loader::load)
                }

        private class HooksLoader(
            private val scanResult: ScanResult,
            val excludeHookClassNames: List<String>,
        ) {
            fun load(hookClassNames: Set<String>): Hooks {
                val hooksWithHookClasses = hookClassNames.flatMap(::loadHooks)
                val hooks = hooksWithHookClasses.map { it.first }
                val hookClasses = hooksWithHookClasses.map { it.second }.toSet()
                val additionalHookClassNameGlobber =
                    ClassNameGlobber(
                        hooks.flatMap(Hook::additionalClassesToHook),
                        excludeHookClassNames,
                    )
                return Hooks(hooks, hookClasses, additionalHookClassNameGlobber)
            }

            private fun loadHooks(hookClassName: String): List<Pair<Hook, Class<*>>> =
                try {
                    // We let the static initializers of hook classes execute so that hooks can run
                    // code before the fuzz target class has been loaded (e.g., register themselves
                    // for the onFuzzTargetReady callback).
                    val hookClass =
                        Class.forName(hookClassName, true, Companion::class.java.classLoader)
                    loadHooks(hookClass)
                        .also {
                            Log.info("Loaded ${it.size} hooks from $hookClassName")
                        }.map {
                            it to hookClass
                        }
                } catch (e: ClassNotFoundException) {
                    Log.warn("Failed to load hooks from $hookClassName", e)
                    emptyList()
                }

            private fun loadHooks(hookClass: Class<*>): List<Hook> {
                val hooks = mutableListOf<Hook>()
                for (method in hookClass.methods.sortedBy { it.descriptor }) {
                    method.getAnnotation(MethodHook::class.java)?.let {
                        hooks.addAll(verifyAndGetHooks(method, it))
                    }
                    method.getAnnotation(MethodHooks::class.java)?.let {
                        it.value.forEach { hookAnnotation ->
                            hooks.addAll(verifyAndGetHooks(method, hookAnnotation))
                        }
                    }
                }
                return hooks
            }

            private fun verifyAndGetHooks(
                hookMethod: Method,
                hookData: MethodHook,
            ): List<Hook> =
                lookupClassesToHook(hookData.targetClassName)
                    .map { className ->
                        Hook.createAndVerifyHook(hookMethod, hookData, className)
                    }

            private fun lookupClassesToHook(annotationTargetClassName: String): List<String> {
                // Allowing arbitrary exterior whitespace in the target class name allows for an easy workaround
                // for mangled hooks due to shading applied to hooks.
                val targetClassName = annotationTargetClassName.trim()
                val targetClassInfo = scanResult.getClassInfo(targetClassName) ?: return listOf(targetClassName)
                val additionalTargetClasses =
                    when {
                        targetClassInfo.isInterface -> scanResult.getClassesImplementing(targetClassName)
                        targetClassInfo.isAbstract -> scanResult.getSubclasses(targetClassName)
                        else -> emptyList()
                    }
                return (listOf(targetClassName) + additionalTargetClasses.map { it.name }).sorted()
            }
        }
    }
}
