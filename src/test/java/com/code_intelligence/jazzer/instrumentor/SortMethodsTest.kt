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
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.tree.ClassNode
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class SortMethodsTest {
    private fun readClass(bytecode: ByteArray): ClassNode = ClassNode().also { ClassReader(bytecode).accept(it, 0) }

    private fun methodSignatures(bytecode: ByteArray): List<Pair<String, String>> = readClass(bytecode).methods.map { it.name to it.desc }

    private fun reverseMethods(bytecode: ByteArray): ByteArray {
        val reader = ClassReader(bytecode)
        val node = ClassNode()
        reader.accept(node, 0)
        node.methods.reverse()
        val writer = ClassWriter(reader, 0)
        node.accept(writer)
        return writer.toByteArray()
    }

    @Test
    fun testSortMethodsIsIndependentOfMethodOrder() {
        val original = classToBytecode(CoverageInstrumentationTarget::class.java)
        val reversed = reverseMethods(original)
        assertNotEquals(methodSignatures(original), methodSignatures(reversed))

        val sorted = sortMethods(original)
        assertEquals(methodSignatures(original).sortedWith(compareBy({ it.first }, { it.second })), methodSignatures(sorted))
        assertContentEquals(sorted, sortMethods(reversed))
    }
}
