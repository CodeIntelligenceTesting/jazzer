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
