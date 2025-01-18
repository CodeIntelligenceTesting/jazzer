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

import com.code_intelligence.jazzer.instrumentor.PatchTestUtils.bytecodeToClass
import com.code_intelligence.jazzer.instrumentor.PatchTestUtils.classToBytecode
import org.junit.Test
import java.io.File

private fun getOriginalReplaceHooksTargetInstance(): ReplaceHooksTargetContract = ReplaceHooksTarget()

private fun getNoHooksReplaceHooksTargetInstance(): ReplaceHooksTargetContract {
    val originalBytecode = classToBytecode(ReplaceHooksTarget::class.java)
    // Let the bytecode pass through the hooking logic, but don't apply any hooks.
    val patchedBytecode =
        HookInstrumentor(emptyList(), false, null).instrument(
            ReplaceHooksTarget::class.java.name.replace('.', '/'),
            originalBytecode,
        )
    val patchedClass = bytecodeToClass(ReplaceHooksTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as ReplaceHooksTargetContract
}

private fun getPatchedReplaceHooksTargetInstance(classWithHooksEnabledField: Class<*>?): ReplaceHooksTargetContract {
    val originalBytecode = classToBytecode(ReplaceHooksTarget::class.java)
    val hooks = Hooks.loadHooks(emptyList(), setOf(ReplaceHooks::class.java.name)).first().hooks
    val patchedBytecode =
        HookInstrumentor(
            hooks,
            false,
            classWithHooksEnabledField = classWithHooksEnabledField?.name?.replace('.', '/'),
        ).instrument(ReplaceHooksTarget::class.java.name.replace('.', '/'), originalBytecode)
    // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
    val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
    File("$outDir/${ReplaceHooksTarget::class.java.simpleName}.class").writeBytes(originalBytecode)
    File("$outDir/${ReplaceHooksTarget::class.java.simpleName}.patched.class").writeBytes(patchedBytecode)
    val patchedClass = bytecodeToClass(ReplaceHooksTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as ReplaceHooksTargetContract
}

@Suppress("ktlint:standard:property-naming")
class ReplaceHooksPatchTest {
    @Test
    fun testOriginal() {
        assertSelfCheck(getOriginalReplaceHooksTargetInstance(), false)
    }

    @Test
    fun testPatchedWithoutHooks() {
        assertSelfCheck(getNoHooksReplaceHooksTargetInstance(), false)
    }

    @Test
    fun testPatched() {
        assertSelfCheck(getPatchedReplaceHooksTargetInstance(null), true)
    }

    object HooksEnabled {
        @Suppress("unused")
        const val hooksEnabled = true
    }

    object HooksDisabled {
        @Suppress("unused")
        const val hooksEnabled = false
    }

    @Test
    fun testPatchedWithConditionalHooksEnabled() {
        assertSelfCheck(getPatchedReplaceHooksTargetInstance(HooksEnabled::class.java), true)
    }

    @Test
    fun testPatchedWithConditionalHooksDisabled() {
        assertSelfCheck(getPatchedReplaceHooksTargetInstance(HooksDisabled::class.java), false)
    }
}
