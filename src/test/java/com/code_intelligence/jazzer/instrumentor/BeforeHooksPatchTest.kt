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

import com.code_intelligence.jazzer.instrumentor.PatchTestUtils.bytecodeToClass
import com.code_intelligence.jazzer.instrumentor.PatchTestUtils.classToBytecode
import org.junit.Test
import java.io.File

private fun getOriginalBeforeHooksTargetInstance(): BeforeHooksTargetContract {
    return BeforeHooksTarget()
}

private fun getNoHooksBeforeHooksTargetInstance(): BeforeHooksTargetContract {
    val originalBytecode = classToBytecode(BeforeHooksTarget::class.java)
    // Let the bytecode pass through the hooking logic, but don't apply any hooks.
    val patchedBytecode = HookInstrumentor(emptyList(), false, null).instrument(
        BeforeHooksTarget::class.java.name.replace('.', '/'),
        originalBytecode,
    )
    val patchedClass = bytecodeToClass(BeforeHooksTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as BeforeHooksTargetContract
}

private fun getPatchedBeforeHooksTargetInstance(classWithHooksEnabledField: Class<*>?): BeforeHooksTargetContract {
    val originalBytecode = classToBytecode(BeforeHooksTarget::class.java)
    val hooks = Hooks.loadHooks(emptyList(), setOf(BeforeHooks::class.java.name)).first().hooks
    val patchedBytecode = HookInstrumentor(
        hooks,
        false,
        classWithHooksEnabledField = classWithHooksEnabledField?.name?.replace('.', '/'),
    ).instrument(BeforeHooksTarget::class.java.name.replace('.', '/'), originalBytecode)
    // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
    val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
    File("$outDir/${BeforeHooksTarget::class.java.simpleName}.class").writeBytes(originalBytecode)
    File("$outDir/${BeforeHooksTarget::class.java.simpleName}.patched.class").writeBytes(patchedBytecode)
    val patchedClass = bytecodeToClass(BeforeHooksTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as BeforeHooksTargetContract
}

class BeforeHooksPatchTest {

    @Test
    fun testOriginal() {
        assertSelfCheck(getOriginalBeforeHooksTargetInstance(), false)
    }

    @Test
    fun testPatchedWithoutHooks() {
        assertSelfCheck(getNoHooksBeforeHooksTargetInstance(), false)
    }

    @Test
    fun testPatched() {
        assertSelfCheck(getPatchedBeforeHooksTargetInstance(null), true)
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
        assertSelfCheck(getPatchedBeforeHooksTargetInstance(HooksEnabled::class.java), true)
    }

    @Test
    fun testPatchedWithConditionalHooksDisabled() {
        assertSelfCheck(getPatchedBeforeHooksTargetInstance(HooksDisabled::class.java), false)
    }
}
