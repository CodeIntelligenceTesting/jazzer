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
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.io.File
import kotlin.test.assertEquals

/**
 * Amends the instrumentation performed by [strategy] to call the map's public static void method
 * updated() after every update to coverage counters.
 */
private fun makeTestable(strategy: EdgeCoverageStrategy): EdgeCoverageStrategy =
    object : EdgeCoverageStrategy by strategy {
        override fun instrumentControlFlowEdge(
            mv: MethodVisitor,
            edgeId: Int,
            variable: Int,
            coverageMapInternalClassName: String,
        ) {
            strategy.instrumentControlFlowEdge(mv, edgeId, variable, coverageMapInternalClassName)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, coverageMapInternalClassName, "updated", "()V", false)
        }
    }

private fun getOriginalInstrumentationTargetInstance(): DynamicTestContract = CoverageInstrumentationTarget()

private fun getInstrumentedInstrumentationTargetInstance(): DynamicTestContract {
    val originalBytecode = classToBytecode(CoverageInstrumentationTarget::class.java)
    val patchedBytecode =
        EdgeCoverageInstrumentor(
            makeTestable(ClassInstrumentor.defaultEdgeCoverageStrategy),
            MockCoverageMap::class.java,
            0,
        ).instrument(CoverageInstrumentationTarget::class.java.name.replace('.', '/'), originalBytecode)
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

@Suppress("unused")
class CoverageInstrumentationTest {
    private val constructorReturn = 0

    private val mapConstructor = 1
    private val addFor0 = 2
    private val addFor1 = 3
    private val addFor2 = 4
    private val addFor3 = 5
    private val addFor4 = 6
    private val addFoobar = 7

    private val ifTrueBranch = 8
    private val addBlock1 = 9
    private val ifFalseBranch = 10
    private val ifEnd = 11

    private val outerForCondition = 12
    private val innerForCondition = 13
    private val innerForBodyIfTrueBranch = 14
    private val innerForBodyIfFalseBranch = 15
    private val innerForBodyPutInvocation = 16
    private val outerForIncrementCounter = 17

    private val afterFooInvocation = 18
    private val fooAfterBarInvocation = 19
    private val barAfterPutInvocation = 20

    @Test
    fun testOriginal() {
        assertSelfCheck(getOriginalInstrumentationTargetInstance())
    }

    @Test
    fun testInstrumented() {
        MockCoverageMap.clear()
        assertSelfCheck(getInstrumentedInstrumentationTargetInstance())

        val mapControlFlow = listOf(mapConstructor, addFor0, addFor1, addFor2, addFor3, addFor4, addFoobar)
        val ifControlFlow = listOf(ifTrueBranch, addBlock1, ifEnd)
        val forFirstRunControlFlow =
            mutableListOf<Int>()
                .apply {
                    add(outerForCondition)
                    repeat(5) {
                        addAll(listOf(innerForCondition, innerForBodyIfFalseBranch, innerForBodyPutInvocation))
                    }
                    add(outerForIncrementCounter)
                }.toList()
        val forSecondRunControlFlow =
            mutableListOf<Int>()
                .apply {
                    add(outerForCondition)
                    repeat(5) {
                        addAll(listOf(innerForCondition, innerForBodyIfTrueBranch, innerForBodyPutInvocation))
                    }
                    add(outerForIncrementCounter)
                }.toList()
        val forControlFlow = forFirstRunControlFlow + forSecondRunControlFlow
        val fooCallControlFlow =
            listOf(
                barAfterPutInvocation,
                fooAfterBarInvocation,
                afterFooInvocation,
            )
        assertControlFlow(
            listOf(constructorReturn) +
                mapControlFlow +
                ifControlFlow +
                forControlFlow +
                fooCallControlFlow,
        )
    }

    @Test
    fun testCounters() {
        MockCoverageMap.clear()

        val target = getInstrumentedInstrumentationTargetInstance()
        // The constructor of the target is run only once.
        val takenOnceEdge = constructorReturn
        // Control flows through the first if branch once per run.
        val takenOnEveryRunEdge = ifTrueBranch

        var lastCounter = 0.toUByte()
        for (i in 1..600) {
            assertSelfCheck(target)
            assertEquals(1, MockCoverageMap.counters[takenOnceEdge])
            // Verify that the counter increments, but is never zero.
            val expectedCounter =
                (lastCounter + 1U).toUByte().takeUnless { it == 0.toUByte() }
                    ?: (lastCounter + 2U).toUByte()
            lastCounter = expectedCounter
            val actualCounter = MockCoverageMap.counters[takenOnEveryRunEdge].toUByte()
            assertEquals(expectedCounter, actualCounter, "After $i runs:")
        }
    }

    @Test
    fun testSpecialCases() {
        val originalBytecode = classToBytecode(CoverageInstrumentationSpecialCasesTarget::class.java)
        val patchedBytecode =
            EdgeCoverageInstrumentor(
                makeTestable(ClassInstrumentor.defaultEdgeCoverageStrategy),
                MockCoverageMap::class.java,
                0,
            ).instrument(CoverageInstrumentationSpecialCasesTarget::class.java.name.replace('.', '/'), originalBytecode)
        // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
        val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
        File("$outDir/${CoverageInstrumentationSpecialCasesTarget::class.simpleName}.class").writeBytes(originalBytecode)
        File("$outDir/${CoverageInstrumentationSpecialCasesTarget::class.simpleName}.patched.class").writeBytes(
            patchedBytecode,
        )
        val patchedClass = bytecodeToClass(CoverageInstrumentationSpecialCasesTarget::class.java.name, patchedBytecode)
        // Trigger a class load
        patchedClass.declaredMethods
    }
}
