/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 *
 * This file also contains code licensed under Apache2 license.
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

        fun appendHooksToBootstrapClassLoaderSearch(instrumentation: Instrumentation, hookClassNames: Set<String>) {
            hookClassNames.mapNotNull { hook ->
                val hookClassFilePath = "/${hook.replace('.', '/')}.class"
                val hookClassFile = Companion::class.java.getResource(hookClassFilePath) ?: return@mapNotNull null
                if ("jar" != hookClassFile.protocol) {
                    return@mapNotNull null
                }
                // hookClassFile.file looks as follows:
                // file:/tmp/ExampleFuzzerHooks_deploy.jar!/com/example/ExampleFuzzerHooks.class
                hookClassFile.file.removePrefix("file:").takeWhile { it != '!' }
            }
                .toSet()
                .map { JarFile(it) }
                .forEach { instrumentation.appendToBootstrapClassLoaderSearch(it) }
        }

        fun loadHooks(excludeHookClassNames: List<String>, vararg hookClassNames: Set<String>): List<Hooks> {
            return ClassGraph()
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
        }

        private class HooksLoader(private val scanResult: ScanResult, val excludeHookClassNames: List<String>) {

            fun load(hookClassNames: Set<String>): Hooks {
                val hooksWithHookClasses = hookClassNames.flatMap(::loadHooks)
                val hooks = hooksWithHookClasses.map { it.first }
                val hookClasses = hooksWithHookClasses.map { it.second }.toSet()
                val additionalHookClassNameGlobber = ClassNameGlobber(
                    hooks.flatMap(Hook::additionalClassesToHook),
                    excludeHookClassNames,
                )
                return Hooks(hooks, hookClasses, additionalHookClassNameGlobber)
            }

            private fun loadHooks(hookClassName: String): List<Pair<Hook, Class<*>>> {
                return try {
                    // We let the static initializers of hook classes execute so that hooks can run
                    // code before the fuzz target class has been loaded (e.g., register themselves
                    // for the onFuzzTargetReady callback).
                    val hookClass =
                        Class.forName(hookClassName, true, Companion::class.java.classLoader)
                    loadHooks(hookClass).also {
                        Log.info("Loaded ${it.size} hooks from $hookClassName")
                    }.map {
                        it to hookClass
                    }
                } catch (e: ClassNotFoundException) {
                    Log.warn("Failed to load hooks from $hookClassName", e)
                    emptyList()
                }
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

            private fun verifyAndGetHooks(hookMethod: Method, hookData: MethodHook): List<Hook> {
                return lookupClassesToHook(hookData.targetClassName)
                    .map { className ->
                        Hook.createAndVerifyHook(hookMethod, hookData, className)
                    }
            }

            private fun lookupClassesToHook(annotationTargetClassName: String): List<String> {
                // Allowing arbitrary exterior whitespace in the target class name allows for an easy workaround
                // for mangled hooks due to shading applied to hooks.
                val targetClassName = annotationTargetClassName.trim()
                val targetClassInfo = scanResult.getClassInfo(targetClassName) ?: return listOf(targetClassName)
                val additionalTargetClasses = when {
                    targetClassInfo.isInterface -> scanResult.getClassesImplementing(targetClassName)
                    targetClassInfo.isAbstract -> scanResult.getSubclasses(targetClassName)
                    else -> emptyList()
                }
                return (listOf(targetClassName) + additionalTargetClasses.map { it.name }).sorted()
            }
        }
    }
}
