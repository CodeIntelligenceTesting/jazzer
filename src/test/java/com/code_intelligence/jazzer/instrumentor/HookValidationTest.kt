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
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HookValidationTest {
    @Test
    fun testValidHooks() {
        val hooks = Hooks.loadHooks(emptyList(), setOf(ValidHookMocks::class.java.name)).first().hooks
        assertEquals(5, hooks.size)
    }

    @Test
    fun testInvalidHooks() {
        for (method in InvalidHookMocks::class.java.methods) {
            if (method.isAnnotationPresent(MethodHook::class.java)) {
                assertFailsWith<IllegalArgumentException>("Expected ${method.name} to be an invalid hook") {
                    val methodHook = method.declaredAnnotations.first() as MethodHook
                    Hook.createAndVerifyHook(method, methodHook, methodHook.targetClassName)
                }
            }
        }
    }
}
