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

import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

object DirectByteBufferStrategy : EdgeCoverageStrategy {
    override fun instrumentControlFlowEdge(
        mv: MethodVisitor,
        edgeId: Int,
        variable: Int,
        coverageMapInternalClassName: String,
    ) {
        mv.apply {
            visitVarInsn(Opcodes.ALOAD, variable)
            // Stack: counters
            push(edgeId)
            // Stack: counters | edgeId
            visitInsn(Opcodes.DUP2)
            // Stack: counters | edgeId | counters | edgeId
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/nio/ByteBuffer", "get", "(I)B", false)
            // Increment the counter, but ensure that it never stays at 0 after an overflow by incrementing it again in
            // that case.
            // This approach performs better than saturating the counter at 255 (see Section 3.3 of
            // https://www.usenix.org/system/files/woot20-paper-fioraldi.pdf)
            // Stack: counters | edgeId | counter (sign-extended to int)
            push(0xff)
            // Stack: counters | edgeId | counter (sign-extended to int) | 0x000000ff
            visitInsn(Opcodes.IAND)
            // Stack: counters | edgeId | counter (zero-extended to int)
            push(1)
            // Stack: counters | edgeId | counter | 1
            visitInsn(Opcodes.IADD)
            // Stack: counters | edgeId | counter + 1
            visitInsn(Opcodes.DUP)
            // Stack: counters | edgeId | counter + 1 | counter + 1
            push(8)
            // Stack: counters | edgeId | counter + 1 | counter + 1 | 8 (maxStack: +5)
            visitInsn(Opcodes.ISHR)
            // Stack: counters | edgeId | counter + 1 | 1 if the increment overflowed to 0, 0 otherwise
            visitInsn(Opcodes.IADD)
            // Stack: counters | edgeId | counter + 2 if the increment overflowed, counter + 1 otherwise
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/nio/ByteBuffer", "put", "(IB)Ljava/nio/ByteBuffer;", false)
            // Stack: counters
            visitInsn(Opcodes.POP)
        }
    }

    override val instrumentControlFlowEdgeStackSize = 5

    override val localVariableType get() = "java/nio/ByteBuffer"

    override fun loadLocalVariable(
        mv: MethodVisitor,
        variable: Int,
        coverageMapInternalClassName: String,
    ) {
        mv.apply {
            visitFieldInsn(
                Opcodes.GETSTATIC,
                coverageMapInternalClassName,
                "counters",
                "Ljava/nio/ByteBuffer;",
            )
            // Stack: counters (maxStack: 1)
            visitVarInsn(Opcodes.ASTORE, variable)
        }
    }

    override val loadLocalVariableStackSize = 1
}
