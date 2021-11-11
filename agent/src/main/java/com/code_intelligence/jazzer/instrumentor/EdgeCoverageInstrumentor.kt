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
import com.code_intelligence.jazzer.third_party.jacoco.core.analysis.Analyzer
import com.code_intelligence.jazzer.third_party.jacoco.core.analysis.ICoverageVisitor
import com.code_intelligence.jazzer.third_party.jacoco.core.data.ExecutionDataStore
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.flow.ClassProbesAdapter
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.flow.ClassProbesVisitor
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.flow.IClassProbesAdapterFactory
import com.code_intelligence.jazzer.third_party.jacoco.core.internal.flow.JavaNoThrowMethods
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
    init {
        if (isTesting) {
            JavaNoThrowMethods.isTesting = true
        }
    }

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

    fun analyze(executionData: ExecutionDataStore, coverageVisitor: ICoverageVisitor, bytecode: ByteArray, internalClassName: String) {
        Analyzer(executionData, coverageVisitor, edgeCoverageClassProbesAdapterFactory).run {
            analyzeClass(bytecode, internalClassName)
        }
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

// The remainder of this file interfaces with classes in org.jacoco.core.internal. Changes to this part should not be
// necessary unless JaCoCo is updated or the way we instrument for coverage changes fundamentally.

    /**
     * A [ProbeInserter] that injects the bytecode instrumentation returned by [instrumentControlFlowEdge] and modifies
     * the stack size and number of local variables accordingly.
     */
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
            val newMaxStack = max(maxStack + instrumentControlFlowEdgeStackSize, loadCoverageMapStackSize)
            mv.visitMaxs(newMaxStack, maxLocals + 1)
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

    private val edgeCoverageClassProbesAdapterFactory = IClassProbesAdapterFactory { probesVisitor, trackFrames ->
        EdgeCoverageClassProbesAdapter(probesVisitor, trackFrames)
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
