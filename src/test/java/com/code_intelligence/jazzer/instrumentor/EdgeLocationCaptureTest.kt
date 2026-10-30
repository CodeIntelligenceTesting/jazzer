/*
 * Copyright 2026 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.instrumentor.PatchTestUtils.classToBytecode
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class EdgeLocationCaptureTest {
    @Test
    fun testEdgeLocationCapture() {
        val internalClassName = CoverageInstrumentationTarget::class.java.name.replace('.', '/')
        val instrumentor =
            EdgeCoverageInstrumentor(
                ClassInstrumentor.defaultEdgeCoverageStrategy,
                MockCoverageMap::class.java,
                0,
            )
        instrumentor.instrument(internalClassName, classToBytecode(CoverageInstrumentationTarget::class.java))

        val locations = instrumentor.buildEdgeLocations()
        assertNotNull(locations, "Expected non-null locations for a class with edges")

        // Source file should combine the package prefix with the SourceFile attribute.
        assertEquals(
            "com/code_intelligence/jazzer/instrumentor/CoverageInstrumentationTarget.java",
            locations.sourceFile,
        )

        // Method names should be qualified as SimpleClassName.method.
        assertTrue(
            locations.methodNames.any { it == "CoverageInstrumentationTarget.<init>" },
            "Expected constructor in method names, got: ${locations.methodNames.toList()}",
        )
        assertTrue(
            locations.methodNames.any { it == "CoverageInstrumentationTarget.selfCheck" },
            "Expected selfCheck in method names, got: ${locations.methodNames.toList()}",
        )

        // Flat array must have exactly 2 ints per edge (packedLine, methodIdx).
        assertEquals(instrumentor.numEdges * 2, locations.edgeData.size)

        // First edge should have the function-entry bit set (sign bit).
        val firstPackedLine = locations.edgeData[0]
        assertTrue(firstPackedLine < 0, "First edge should have function-entry bit (sign bit) set")

        // Its actual line number should be positive (class was compiled with debug info).
        val firstLine = firstPackedLine and 0x7FFFFFFF
        assertTrue(firstLine > 0, "Line number should be > 0 for a class with debug info")

        // Second edge of the same method should NOT have the function-entry bit set.
        // Find the second edge that shares the same methodIdx as the first.
        val firstMethodIdx = locations.edgeData[1]
        for (i in 1 until instrumentor.numEdges) {
            if (locations.edgeData[2 * i + 1] == firstMethodIdx) {
                val subsequentPackedLine = locations.edgeData[2 * i]
                assertTrue(subsequentPackedLine >= 0, "Subsequent edge should not have function-entry bit")
                break
            }
        }
    }
}
