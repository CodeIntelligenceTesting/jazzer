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
import kotlin.test.assertEquals

private fun applyInstrumentation(bytecode: ByteArray): ByteArray {
    return EdgeCoverageInstrumentor(0, MockCoverageMap::class.java).instrument(bytecode)
}

private fun getOriginalInstrumentationTargetInstance(): DynamicTestContract {
    return CoverageInstrumentationTarget()
}

private fun getInstrumentedInstrumentationTargetInstance(): DynamicTestContract {
    val originalBytecode = classToBytecode(CoverageInstrumentationTarget::class.java)
    val patchedBytecode = applyInstrumentation(originalBytecode)
    // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
    val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
    File("$outDir/${CoverageInstrumentationTarget::class.java.simpleName}.class").writeBytes(originalBytecode)
    File("$outDir/${CoverageInstrumentationTarget::class.java.simpleName}.patched.class").writeBytes(patchedBytecode)
    val patchedClass = bytecodeToClass(CoverageInstrumentationTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as DynamicTestContract
}

private fun assertControlFlow(expectedLocations: List<Int>) {
    assertEquals(expectedLocations, MockCoverageMap.locations.toList())
}

class CoverageInstrumentationTest {

    private val constructorReturn = 0
    private val ifFirstBranch = 1
    @Suppress("unused")
    private val ifSecondBranch = 2
    private val ifEnd = 3
    private val outerForCondition = 4
    private val innerForBodyIfFirstRun = 6
    private val innerForBodyIfSecondRun = 5
    private val innerForIncrementCounter = 7
    private val outerForIncrementCounter = 8
    private val afterFooInvocation = 9
    private val beforeReturn = 10
    private val fooAfterBarInvocation = 11
    private val fooBeforeReturn = 12
    private val barAfterMapPutInvocation = 13
    private val barBeforeReturn = 14
    @Suppress("unused")
    private val bazReturn = 15

    @Test
    fun testOriginal() {
        assertSelfCheck(getOriginalInstrumentationTargetInstance())
    }

    @Test
    fun testInstrumented() {
        MockCoverageMap.clear()
        assertSelfCheck(getInstrumentedInstrumentationTargetInstance())

        val innerForFirstRunControlFlow = mutableListOf<Int>().apply {
            repeat(5) {
                addAll(listOf(innerForBodyIfFirstRun, innerForIncrementCounter))
            }
        }.toList()
        val innerForSecondRunControlFlow = mutableListOf<Int>().apply {
            repeat(5) {
                addAll(listOf(innerForBodyIfSecondRun, innerForIncrementCounter))
            }
        }.toList()
        val outerForControlFlow =
            listOf(outerForCondition) +
                innerForFirstRunControlFlow +
                listOf(outerForIncrementCounter, outerForCondition) +
                innerForSecondRunControlFlow +
                listOf(outerForIncrementCounter)

        assertControlFlow(
            listOf(constructorReturn, ifFirstBranch, ifEnd) +
                outerForControlFlow +
                listOf(
                    barAfterMapPutInvocation, barBeforeReturn,
                    fooAfterBarInvocation, fooBeforeReturn,
                    afterFooInvocation, beforeReturn
                )
        )
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun testCounters() {
        MockCoverageMap.clear()

        val target = getInstrumentedInstrumentationTargetInstance()
        // The constructor of the target is run only once.
        val takenOnceEdge = constructorReturn
        // Control flows through the first if branch once per run.
        val takenOnEveryRunEdge = ifFirstBranch

        var lastCounter = 0.toUByte()
        for (i in 1..600) {
            assertSelfCheck(target)
            assertEquals(1, MockCoverageMap.mem[takenOnceEdge])
            // Verify that the counter increments, but is never zero.
            val expectedCounter = (lastCounter + 1U).toUByte().takeUnless { it == 0.toUByte() }
                ?: (lastCounter + 2U).toUByte()
            lastCounter = expectedCounter
            val actualCounter = MockCoverageMap.mem[takenOnEveryRunEdge].toUByte()
            assertEquals(expectedCounter, actualCounter, "After $i runs:")
        }
    }

    @Test
    fun testSpecialCases() {
        val originalBytecode = classToBytecode(CoverageInstrumentationSpecialCasesTarget::class.java)
        val patchedBytecode = applyInstrumentation(originalBytecode)
        // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
        val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
        File("$outDir/${CoverageInstrumentationSpecialCasesTarget::class.simpleName}.class").writeBytes(originalBytecode)
        File("$outDir/${CoverageInstrumentationSpecialCasesTarget::class.simpleName}.patched.class").writeBytes(
            patchedBytecode
        )
        val patchedClass = bytecodeToClass(CoverageInstrumentationSpecialCasesTarget::class.java.name, patchedBytecode)
        // Trigger a class load
        patchedClass.declaredMethods
    }
}
