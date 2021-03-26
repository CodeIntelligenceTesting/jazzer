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

import com.code_intelligence.jazzer.generated.JAVA_NO_THROW_METHODS
import com.code_intelligence.jazzer.runtime.CoverageMap
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.flow.ClassProbesAdapter
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.flow.ClassProbesVisitor
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.instr.ClassInstrumenter
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.instr.IProbeArrayStrategy
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.instr.IProbeInserterFactory
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.instr.InstrSupport
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.instr.ProbeInserter
import com.code_intelligence.jazzer.third_party.objectweb.asm.ClassReader
import com.code_intelligence.jazzer.third_party.objectweb.asm.ClassVisitor
import com.code_intelligence.jazzer.third_party.objectweb.asm.ClassWriter
import com.code_intelligence.jazzer.third_party.objectweb.asm.MethodVisitor
import com.code_intelligence.jazzer.third_party.objectweb.asm.Opcodes
import kotlin.math.max

class EdgeCoverageInstrumentor(
    private val initialEdgeId: Int,
    private val coverageMapClass: Class<*> = CoverageMap::class.java
) : Instrumentor {
    private var nextEdgeId = initialEdgeId
    private val coverageMapInternalClassName = coverageMapClass.name.replace('.', '/')

    override fun instrument(bytecode: ByteArray): ByteArray {
        val reader = InstrSupport.classReaderFor(bytecode)
        val writer = ClassWriter(reader, 0)
        val version = InstrSupport.getMajorVersion(reader)
        val visitor = EdgeCoverageClassProbesAdapter(
            ClassInstrumenter(edgeCoverageProbeArrayStrategy, edgeCoverageProbeInserterFactory, writer),
            InstrSupport.needsFrames(version)
        )
        reader.accept(visitor, ClassReader.EXPAND_FRAMES)
        return writer.toByteArray()
    }

    val numEdges
        get() = nextEdgeId - initialEdgeId

    private val isTesting
        get() = coverageMapClass != CoverageMap::class.java

    private fun nextEdgeId(): Int {
        if (nextEdgeId >= CoverageMap.mem.capacity()) {
            if (!isTesting) {
                CoverageMap.enlargeCoverageMap()
            }
        }
        return nextEdgeId++
    }

    /**
     * The maximal number of stack elements used by [loadCoverageMap].
     */
    private val loadCoverageMapStackSize = 1

    /**
     * Inject bytecode that loads the coverage map into local variable [variable].
     */
    private fun loadCoverageMap(mv: MethodVisitor, variable: Int) {
        mv.apply {
            visitFieldInsn(
                Opcodes.GETSTATIC,
                coverageMapInternalClassName,
                "mem",
                "Ljava/nio/ByteBuffer;"
            )
            // Stack: mem (maxStack: 1)
            visitVarInsn(Opcodes.ASTORE, variable)
        }
    }

    /**
     * The maximal number of stack elements used by [instrumentControlFlowEdge].
     */
    private val instrumentControlFlowEdgeStackSize = 5

    /**
     * Inject bytecode instrumentation on a control flow edge with ID [edgeId]. The coverage map can be loaded from
     * local variable [variable].
     */
    private fun instrumentControlFlowEdge(mv: MethodVisitor, edgeId: Int, variable: Int) {
        mv.apply {
            visitVarInsn(Opcodes.ALOAD, variable)
            // Stack: mem
            push(edgeId)
            // Stack: mem | edgeId
            visitInsn(Opcodes.DUP2)
            // Stack: mem | edgeId | mem | edgeId
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/nio/ByteBuffer", "get", "(I)B", false)
            // Increment the counter, but ensure that it never stays at 0 after an overflow by incrementing it again in
            // that case.
            // This approach performs better than saturating the counter at 255 (see Section 3.3 of
            // https://www.usenix.org/system/files/woot20-paper-fioraldi.pdf)
            // Stack: mem | edgeId | counter (sign-extended to int)
            push(0xff)
            // Stack: mem | edgeId | counter (sign-extended to int) | 0x000000ff
            visitInsn(Opcodes.IAND)
            // Stack: mem | edgeId | counter (zero-extended to int)
            push(1)
            // Stack: mem | edgeId | counter | 1
            visitInsn(Opcodes.IADD)
            // Stack: mem | edgeId | counter + 1
            visitInsn(Opcodes.DUP)
            // Stack: mem | edgeId | counter + 1 | counter + 1
            push(8)
            // Stack: mem | edgeId | counter + 1 | counter + 1 | 8 (maxStack: +5)
            visitInsn(Opcodes.ISHR)
            // Stack: mem | edgeId | counter + 1 | 1 if the increment overflowed to 0, 0 otherwise
            visitInsn(Opcodes.IADD)
            // Stack: mem | edgeId | counter + 2 if the increment overflowed, counter + 1 otherwise
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/nio/ByteBuffer", "put", "(IB)Ljava/nio/ByteBuffer;", false)
            // Stack: mem
            visitInsn(Opcodes.POP)
            if (isTesting) {
                visitMethodInsn(Opcodes.INVOKESTATIC, coverageMapInternalClassName, "updated", "()V", false)
            }
        }
    }

    /**
     * The maximal number of stack elements used by [instrumentMethodEdge].
     */
    private val instrumentMethodEdgeStackSize = instrumentControlFlowEdgeStackSize

    /**
     * Inject bytecode instrumentation right before a method invocation (if needed). The coverage map can be loaded from
     * local variable [variable].
     *
     * Note: Since not every method invocation might need instrumentation, an edge ID should only be generated if needed
     * by calling [nextEdgeId].
     */
    private fun instrumentMethodEdge(
        mv: MethodVisitor,
        variable: Int,
        internalClassName: String,
        methodName: String,
        descriptor: String
    ) {
        if (internalClassName.startsWith("com/code_intelligence/jazzer/") && !isTesting)
            return
        if (isNoThrowMethod(internalClassName, methodName, descriptor))
            return
        instrumentControlFlowEdge(mv, nextEdgeId(), variable)
    }

    /**
     * Checks whether a method is in a list of function known not to throw any exceptions (including subclasses of
     * [java.lang.RuntimeException]).
     *
     * If a method is known not to throw any exceptions, calls to it do not need to be instrumented for coverage as it
     * will always return to the same basic block.
     *
     * Note: According to the JVM specification, a [java.lang.VirtualMachineError] can always be thrown. As it is fatal
     * for all practical purposes, we can ignore errors of this kind for coverage instrumentation.
     */
    private fun isNoThrowMethod(internalClassName: String, methodName: String, descriptor: String): Boolean {
        // We only collect no throw information for the Java standard library.
        if (!internalClassName.startsWith("java/"))
            return false
        val key = "$internalClassName#$methodName#$descriptor"
        return key in JAVA_NO_THROW_METHODS
    }

// The remainder of this file interfaces with classes in org.jacoco.core.internal. Changes to this part should not be
// necessary unless JaCoCo is updated or the way we instrument for coverage changes fundamentally.

    private inner class EdgeCoverageProbeInserter(
        access: Int,
        name: String,
        desc: String,
        mv: MethodVisitor,
        arrayStrategy: IProbeArrayStrategy,
    ) : ProbeInserter(access, name, desc, mv, arrayStrategy) {
        override fun insertProbe(id: Int) {
            instrumentControlFlowEdge(mv, id, variable)
        }

        override fun visitMaxs(maxStack: Int, maxLocals: Int) {
            val maxStackIncrease = max(instrumentControlFlowEdgeStackSize, instrumentMethodEdgeStackSize)
            val newMaxStack = max(maxStack + maxStackIncrease, loadCoverageMapStackSize)
            val newMaxLocals = maxLocals + 1
            mv.visitMaxs(newMaxStack, newMaxLocals)
        }

        override fun visitMethodInsn(
            opcode: Int,
            owner: String,
            name: String,
            descriptor: String,
            isInterface: Boolean
        ) {
            instrumentMethodEdge(mv, variable, owner, name, descriptor)
            mv.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
        }
    }

    private val edgeCoverageProbeInserterFactory =
        IProbeInserterFactory { access, name, desc, mv, arrayStrategy ->
            EdgeCoverageProbeInserter(access, name, desc, mv, arrayStrategy)
        }

    private inner class EdgeCoverageClassProbesAdapter(cv: ClassProbesVisitor, trackFrames: Boolean) :
        ClassProbesAdapter(cv, trackFrames) {
        override fun nextId(): Int = nextEdgeId()
    }

    private val edgeCoverageProbeArrayStrategy = object : IProbeArrayStrategy {
        override fun storeInstance(mv: MethodVisitor, clinit: Boolean, variable: Int): Int {
            loadCoverageMap(mv, variable)
            return loadCoverageMapStackSize
        }

        override fun addMembers(cv: ClassVisitor, probeCount: Int) {}
    }

    private fun MethodVisitor.push(value: Int) {
        InstrSupport.push(this, value)
    }
}
