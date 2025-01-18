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

private fun getOriginalInstrumentationTargetInstance(): DynamicTestContract = TraceDataFlowInstrumentationTarget()

private fun getInstrumentedInstrumentationTargetInstance(): DynamicTestContract {
    val originalBytecode = classToBytecode(TraceDataFlowInstrumentationTarget::class.java)
    val patchedBytecode =
        TraceDataFlowInstrumentor(
            setOf(
                InstrumentationType.CMP,
                InstrumentationType.DIV,
                InstrumentationType.GEP,
            ),
            MockTraceDataFlowCallbacks::class.java.name.replace('.', '/'),
        ).instrument(TraceDataFlowInstrumentationTarget::class.java.name.replace('.', '/'), originalBytecode)
    // Make the patched class available in bazel-testlogs/.../test.outputs for manual inspection.
    val outDir = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR")
    File("$outDir/${TraceDataFlowInstrumentationTarget::class.simpleName}.class").writeBytes(originalBytecode)
    File("$outDir/${TraceDataFlowInstrumentationTarget::class.simpleName}.patched.class").writeBytes(patchedBytecode)
    val patchedClass = bytecodeToClass(TraceDataFlowInstrumentationTarget::class.java.name, patchedBytecode)
    return patchedClass.getDeclaredConstructor().newInstance() as DynamicTestContract
}

class TraceDataFlowInstrumentationTest {
    @Test
    fun testOriginal() {
        MockTraceDataFlowCallbacks.init()
        assertSelfCheck(getOriginalInstrumentationTargetInstance())
        assert(MockTraceDataFlowCallbacks.finish())
    }

    @Test
    fun testInstrumented() {
        MockTraceDataFlowCallbacks.init()
        assertSelfCheck(getInstrumentedInstrumentationTargetInstance())
        listOf(
            // long compares
            "LCMP: 1, 1",
            "LCMP: 2, 3",
            // int compares
            "ICMP: 4, 4",
            "ICMP: 5, 6",
            "ICMP: 5, 6",
            "ICMP: 5, 6",
            "ICMP: 5, 6",
            "ICMP: 5, 6",
            // tableswitch with gap
            "SWITCH: 1200, (1000, 1001, 1003, )",
            // lookupswitch
            "SWITCH: -1200, (200, -1200, -1000, -10, -1, )",
            // (6 / 2) == 3
            "IDIV: 2",
            "ICMP: 3, 3",
            // (3 / 2) == 1
            "LDIV: 2",
            "LCMP: 1, 1",
            // referenceArray[2]
            "GEP: 2",
            // boolArray[2]
            "GEP: 2",
            // byteArray[2] == 2
            "GEP: 2",
            "ICMP: 2, 2",
            // charArray[3] == 3
            "GEP: 3",
            "ICMP: 3, 3",
            // doubleArray[4] == 4
            "GEP: 4",
            // floatArray[5] == 5
            "GEP: 5",
            "CICMP: 0, 0",
            // intArray[6] == 6
            "GEP: 6",
            "ICMP: 6, 6",
            // longArray[7] == 7
            "GEP: 7",
            "LCMP: 7, 7",
            // shortArray[8] == 8
            "GEP: 8",
            "ICMP: 8, 8",
            "GEP: 2",
            "GEP: 3",
            "GEP: 4",
            "GEP: 5",
            "GEP: 6",
            "GEP: 7",
            "GEP: 8",
            "GEP: 9",
            "GEP: 10",
            "GEP: 11",
            "GEP: 12",
            "GEP: 13",
            "ICMP: 0, 20",
            "ICMP: 1, 20",
            "ICMP: 2, 20",
            "ICMP: 3, 20",
            "ICMP: 4, 20",
            "ICMP: 5, 20",
            "ICMP: 6, 20",
            "ICMP: 7, 20",
            "ICMP: 8, 20",
            "ICMP: 9, 20",
            "ICMP: 10, 20",
            "ICMP: 11, 20",
            "ICMP: 12, 20",
            "ICMP: 13, 20",
            "ICMP: 14, 20",
            "ICMP: 15, 20",
            "ICMP: 16, 20",
            "ICMP: 17, 20",
            "ICMP: 18, 20",
            "ICMP: 19, 20",
            "ICMP: 20, 20",
            "GEP: 14",
            "GEP: 15",
            "GEP: 16",
            "GEP: 17",
        ).forEach { assert(MockTraceDataFlowCallbacks.hookCall(it)) }
        assert(MockTraceDataFlowCallbacks.finish())
    }
}
