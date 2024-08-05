/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.invoke.MethodHandle

/**
 * Detects unsafe calls that lead to attacker-controlled class loading.
 *
 * Guide the fuzzer to load honeypot class via [Class.forName] or [ClassLoader.loadClass].
 */
@Suppress("unused_parameter", "unused")
object ReflectiveCall {

    @MethodHooks(
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Class", targetMethod = "forName", targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/Class;"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Class", targetMethod = "forName", targetMethodDescriptor = "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.ClassLoader", targetMethod = "loadClass", targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/Class;"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.ClassLoader", targetMethod = "loadClass", targetMethodDescriptor = "(Ljava/lang/String;Z)Ljava/lang/Class;"),
    )
    @JvmStatic
    fun loadClassHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val className = args[0] as? String ?: return
        Jazzer.guideTowardsEquality(className, HONEYPOT_CLASS_NAME, hookId)
    }

    @MethodHooks(
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Class", targetMethod = "forName", targetMethodDescriptor = "(Ljava/lang/Module;Ljava/lang/String;)Ljava/lang/Class;"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.ClassLoader", targetMethod = "loadClass", targetMethodDescriptor = "(Ljava/lang/Module;Ljava/lang/String;)Ljava/lang/Class;"),
    )
    @JvmStatic
    fun loadClassWithModuleHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val className = args[1] as? String ?: return
        Jazzer.guideTowardsEquality(className, HONEYPOT_CLASS_NAME, hookId)
    }

    @MethodHooks(
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Runtime", targetMethod = "load"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Runtime", targetMethod = "loadLibrary"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.System", targetMethod = "load"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.System", targetMethod = "loadLibrary"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.System", targetMethod = "mapLibraryName"),
        MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.ClassLoader", targetMethod = "findLibrary"),
    )
    @JvmStatic
    fun loadLibraryHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        if (args.isEmpty()) { return }
        val libraryName = args[0] as? String ?: return
        if (libraryName == HONEYPOT_LIBRARY_NAME) {
            Jazzer.reportFindingFromHook(
                FuzzerSecurityIssueHigh("load arbitrary library"),
            )
        }
        Jazzer.guideTowardsEquality(libraryName, HONEYPOT_LIBRARY_NAME, hookId)
    }
}
