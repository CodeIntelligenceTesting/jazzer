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

package com.code_intelligence.jazzer.instrumentor

import org.junit.Test
import java.io.File

private fun applyBeforeHooks(bytecode: ByteArray): ByteArray {
    val hooks = Hooks.loadHooks(setOf(BeforeHooks::class.java.name)).first().hooks
    return HookInstrumentor(hooks, false).instrument(bytecode)
}

private fun getOriginalBeforeHooksTargetInstance(): BeforeHooksTargetContract {
    return BeforeHooksTarget()
}

private fun getNoHooksBeforeHooksTargetInstance(): BeforeHooksTargetContract {
    val originalBytecode = classToBytecode(BeforeHooksTarget::class.java)
    // Let the bytecode pass through the hooking logic, but don't apply any hooks.
    val patchedBytecode = HookInstrumentor(emptyList(), false).instrument(originalBytecode)
    val patchedClass = bytecodeToClass(BeforeHooksTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as BeforeHooksTargetContract
}

private fun getPatchedBeforeHooksTargetInstance(): BeforeHooksTargetContract {
    val originalBytecode = classToBytecode(BeforeHooksTarget::class.java)
    val patchedBytecode = applyBeforeHooks(originalBytecode)
    // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
    val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
    File("$outDir/${BeforeHooksTarget::class.java.simpleName}.class").writeBytes(originalBytecode)
    File("$outDir/${BeforeHooksTarget::class.java.simpleName}.patched.class").writeBytes(patchedBytecode)
    val patchedClass = bytecodeToClass(BeforeHooksTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as BeforeHooksTargetContract
}

class BeforeHookTest {

    @Test
    fun testBeforeHooksOriginal() {
        assertSelfCheck(getOriginalBeforeHooksTargetInstance(), false)
    }

    @Test
    fun testBeforeHooksNoHooks() {
        assertSelfCheck(getNoHooksBeforeHooksTargetInstance(), false)
    }

    @Test
    fun testBeforeHooksPatched() {
        assertSelfCheck(getPatchedBeforeHooksTargetInstance(), true)
    }
}
