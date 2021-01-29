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
    return AFLCoverageMapInstrumentor(MockCoverageMap::class.java).instrument(bytecode)
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

    private val constructorStart = 54445
    private val selfCheckStart = 8397
    private val ifFirstBranch = 1555
    private val ifEnd = 26354
    private val outerForCondition = 37842
    private val outerForBody = 53325
    private val innerForCondition = 38432
    private val innerForBody = 5673
    private val innerForBodyIfFirstRun = 2378
    private val innerForBodyIfSecondRun = 57606
    private val innerForIncrementCounter = 7617
    private val outerForIncrementCounter = 14668
    private val outerForAfter = 9328
    private val fooStart = 32182
    private val barStart = 1381

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
                addAll(listOf(innerForCondition, innerForBody, innerForBodyIfFirstRun, innerForIncrementCounter))
            }
            add(innerForCondition)
        }.toList()
        val innerForSecondRunControlFlow = mutableListOf<Int>().apply {
            repeat(5) {
                addAll(listOf(innerForCondition, innerForBody, innerForBodyIfSecondRun, innerForIncrementCounter))
            }
            add(innerForCondition)
        }.toList()
        val outerForControlFlow = listOf(outerForCondition, outerForBody) +
            innerForFirstRunControlFlow +
            listOf(outerForIncrementCounter, outerForCondition, outerForBody) +
            innerForSecondRunControlFlow +
            listOf(outerForIncrementCounter, outerForCondition)

        assertControlFlow(
            listOf(constructorStart, selfCheckStart, ifFirstBranch, ifEnd) +
                outerForControlFlow +
                listOf(outerForAfter, fooStart, barStart)
        )
    }

    /**
     * Computes the position of the counter in the coverage map to be incremented when control flows
     * from the first member of [blocks] to the second.
     */
    fun edge(blocks: Pair<Int, Int>) = (blocks.first shr 1) xor blocks.second

    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun testCounters() {
        MockCoverageMap.clear()

        val target = getInstrumentedInstrumentationTargetInstance()
        // The constructor of the target is run only once.
        val takenOnceEdge = edge(constructorStart to selfCheckStart)
        // Control flows from the start of selfCheck to the first if branch once per run.
        val takenOnEveryRunEdge = edge(selfCheckStart to ifFirstBranch)

        for (i in 1..300) {
            assertSelfCheck(target)
            assertEquals(1, MockCoverageMap.mem[takenOnceEdge])
            // Verify that the counter does not overflow.
            val expectedCounter = i.coerceAtMost(255).toUByte()
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
        File("$outDir/${CoverageInstrumentationSpecialCasesTarget::class.simpleName}.patched.class").writeBytes(patchedBytecode)
        val patchedClass = bytecodeToClass(CoverageInstrumentationSpecialCasesTarget::class.java.name, patchedBytecode)
        // Trigger a class load
        patchedClass.declaredMethods
    }
}
