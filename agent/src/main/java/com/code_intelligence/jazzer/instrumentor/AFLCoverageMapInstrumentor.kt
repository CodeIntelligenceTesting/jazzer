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

import com.code_intelligence.jazzer.runtime.CoverageMap
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.AnnotationNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FrameNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LineNumberNode
import org.objectweb.asm.tree.LocalVariableNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.TypeInsnNode

internal class AFLCoverageMapInstrumentor(coverageMapClass: Class<*> = CoverageMap::class.java) : Instrumentor {

    private val coverageMapInternalClassName = coverageMapClass.name.replace('.', '/')
    private val testing = coverageMapClass != CoverageMap::class.java
    private lateinit var random: DeterministicRandom

    override fun instrument(bytecode: ByteArray): ByteArray {
        val node = ClassNode()
        val reader = ClassReader(bytecode)
        reader.accept(node, 0)
        random = DeterministicRandom("coverage", node.name)
        for (method in node.methods) {
            if (shouldInstrument(method)) {
                for (inst in instrumentationPoints(method)) {
                    method.instructions.insertBefore(inst, coverageInstrumentation())
                }
                method.instructions.insert(coverageInstrumentation())
            }
        }

        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        node.accept(writer)
        return writer.toByteArray()
    }

    /**
     * Applies bytecode instrumentation equivalent to the branch point code used by AFL.
     * {@link https://lcamtuf.coredump.cx/afl/technical_details.txt}
     */
    private fun coverageInstrumentation(): InsnList {
        // cur_location = <COMPILE_TIME_RANDOM>;
        val cur_location = random.nextInt(CoverageMap.SIZE)
        return InsnList().apply {
            // Perform the following byte increment saturating at 255:
            // mem[cur_location ^ prev_location]++;
            add(FieldInsnNode(Opcodes.GETSTATIC, coverageMapInternalClassName, "mem", "Ljava/nio/ByteBuffer;"))
            // Stack: mem
            add(LdcInsnNode(cur_location))
            // Stack: mem | cur_location
            add(FieldInsnNode(Opcodes.GETSTATIC, coverageMapInternalClassName, "prev_location", "I"))
            // Stack: mem | cur_location | prev_location
            add(InsnNode(Opcodes.IXOR))
            // Stack: mem | cur_location ^ prev_location
            add(InsnNode(Opcodes.DUP2))
            // Stack: mem | cur_location ^ prev_location | mem | cur_location ^ prev_location
            add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/nio/ByteBuffer", "get", "(I)B", false))
            // Stack: mem | cur_location ^ prev_location | counter (sign-extended to int)
            add(IntInsnNode(Opcodes.SIPUSH, 0x00ff))
            // Stack: mem | cur_location ^ prev_location | counter (sign-extended to int) | 0x000000ff
            add(InsnNode(Opcodes.IAND))
            // Stack: mem | cur_location ^ prev_location | counter (zero-extended to int)
            add(InsnNode(Opcodes.ICONST_1))
            // Stack: mem | cur_location ^ prev_location | counter | 1
            add(InsnNode(Opcodes.IADD))
            // Stack: mem | cur_location ^ prev_location | counter + 1
            add(InsnNode(Opcodes.DUP))
            // Stack: mem | cur_location ^ prev_location | counter + 1 | counter + 1
            add(IntInsnNode(Opcodes.BIPUSH, 8))
            // Stack: mem | cur_location ^ prev_location | counter + 1 | counter + 1 | 8
            add(InsnNode(Opcodes.ISHR))
            // Stack: mem | cur_location ^ prev_location | counter + 1 | 1 if the increment overflowed, 0 otherwise
            add(InsnNode(Opcodes.ISUB))
            // Stack: mem | cur_location ^ prev_location | counter if the increment overflowed, counter + 1 otherwise
            add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/nio/ByteBuffer", "put", "(IB)Ljava/nio/ByteBuffer;", false))
            // Stack: mem
            add(InsnNode(Opcodes.POP))
            if (testing) {
                add(MethodInsnNode(Opcodes.INVOKESTATIC, coverageMapInternalClassName, "updated", "()V", false))
            }
            // prev_location = cur_location >> 1;
            add(IntInsnNode(Opcodes.SIPUSH, cur_location shr 1))
            add(FieldInsnNode(Opcodes.PUTSTATIC, coverageMapInternalClassName, "prev_location", "I"))
        }
    }

    private fun skipFixedPositionNodes(node: AbstractInsnNode): AbstractInsnNode? {
        var nextFreeNode: AbstractInsnNode? = node
        while (true) {
            when (nextFreeNode) {
                is LabelNode,
                is LineNumberNode,
                is FrameNode,
                is AnnotationNode,
                is TryCatchBlockNode,
                is LocalVariableNode -> {
                    nextFreeNode = nextFreeNode.next
                }
                is TypeInsnNode -> {
                    // NEW instructions are always accompanied by label nodes that tie them to
                    // `Uninitialized` entries in the stack map table. If a NEW instruction is
                    // a target of a jump, then this label node is reused as the target of the
                    // jump and we must not insert other instrumentations in its place.
                    // Since NEW does not invoke any user-supplied code (which only happens in
                    // <init>), we can simply insert instrumentation after the NEW without
                    // misattributing coverage in all but one case: If the NEW throws an
                    // OutOfMemoryError, coverage for the basic block containing it will not have
                    // been updated.
                    if (nextFreeNode.opcode == Opcodes.NEW) {
                        nextFreeNode = nextFreeNode.next
                    } else {
                        return nextFreeNode
                    }
                }
                else -> return nextFreeNode
            }
        }
    }

    private fun instrumentationPoints(method: MethodNode): Set<AbstractInsnNode> =
        method.instructions.asSequence()
            .filterIsInstance<JumpInsnNode>()
            .flatMap {
                // At a jump node control passes either to the target of the jump (always a
                // label node followed by the actual next instruction) or to the instruction
                // right after the jump (possibly skipping a label). We want to return the
                // instruction prior to the next node that must not remain in the position
                // right after the jump (which is the case for labels, frames and NEW
                // instructions, among others).
                val nextIfJumping = skipFixedPositionNodes(it.label)
                // GOTO is an unconditional jump and execution thus never passes to the
                // next instruction.
                val nextIfNotJumping = if (it.opcode != Opcodes.GOTO) skipFixedPositionNodes(it.next) else null
                listOfNotNull(nextIfJumping, nextIfNotJumping)
            }
            .toSet()
}
