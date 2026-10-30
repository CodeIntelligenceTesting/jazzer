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

import com.code_intelligence.jazzer.third_party.org.jacoco.core.analysis.Analyzer
import com.code_intelligence.jazzer.third_party.org.jacoco.core.analysis.ICoverageVisitor
import com.code_intelligence.jazzer.third_party.org.jacoco.core.data.ExecutionDataStore
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.flow.ClassProbesAdapter
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.flow.ClassProbesVisitor
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.flow.IClassProbesAdapterFactory
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.instr.ClassInstrumenter
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.instr.IProbeArrayStrategy
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.instr.IProbeInserterFactory
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.instr.InstrSupport
import com.code_intelligence.jazzer.third_party.org.jacoco.core.internal.instr.ProbeInserter
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import java.lang.invoke.MethodHandle
import java.lang.invoke.MethodHandles.publicLookup
import java.lang.invoke.MethodType.methodType
import kotlin.math.max

/**
 * A particular way to instrument bytecode for edge coverage using a coverage map class available to
 * hold the collected coverage data at runtime.
 */
interface EdgeCoverageStrategy {
    /**
     * Inject bytecode instrumentation on a control flow edge with ID [edgeId], with access to the
     * local variable [variable] that is populated at the beginning of each method by the
     * instrumentation injected in [loadLocalVariable].
     */
    fun instrumentControlFlowEdge(
        mv: MethodVisitor,
        edgeId: Int,
        variable: Int,
        coverageMapInternalClassName: String,
    )

    /**
     * The maximal number of stack elements used by [instrumentControlFlowEdge].
     */
    val instrumentControlFlowEdgeStackSize: Int

    /**
     * The type of the local variable used by the instrumentation in the format used by
     * [MethodVisitor.visitFrame]'s `local` parameter, or `null` if the instrumentation does not use
     * one.
     * @see https://asm.ow2.io/javadoc/org/objectweb/asm/MethodVisitor.html#visitFrame(int,int,java.lang.Object%5B%5D,int,java.lang.Object%5B%5D)
     */
    val localVariableType: Any?

    /**
     * Inject bytecode that loads the coverage counters of the coverage map class described by
     * [coverageMapInternalClassName] into the local variable [variable].
     */
    fun loadLocalVariable(
        mv: MethodVisitor,
        variable: Int,
        coverageMapInternalClassName: String,
    )

    /**
     * The maximal number of stack elements used by [loadLocalVariable].
     */
    val loadLocalVariableStackSize: Int
}

/**
 * Per-edge source location data collected during instrumentation.
 *
 * @param sourceFile  Qualified source path, e.g. "com/example/Foo.java"
 * @param methodNames Deduplicated method name table (SimpleClassName.method)
 * @param edgeData    Flat array: [packedLine0, methodIdx0, packedLine1, methodIdx1, ...]
 *                    The sign bit of each packedLine encodes isFunctionEntry.
 */
class EdgeLocationData(
    val sourceFile: String,
    val methodNames: Array<String>,
    val edgeData: IntArray,
) {
    override fun toString(): String = "EdgeLocationData(sourceFile=$sourceFile, methods=${methodNames.size}, edges=${edgeData.size / 2})"
}

// An instance of EdgeCoverageInstrumentor should only be used to instrument a single class as it
// internally tracks the edge IDs, which have to be globally unique.
class EdgeCoverageInstrumentor(
    private val strategy: EdgeCoverageStrategy,
    /**
     * The class must have the following public static member
     *  - method enlargeIfNeeded(int nextEdgeId): Called before a new edge ID is emitted.
     */
    coverageMapClass: Class<*>,
    private val initialEdgeId: Int,
) : Instrumentor {
    private var nextEdgeId = initialEdgeId

    private val coverageMapInternalClassName = coverageMapClass.name.replace('.', '/')
    private val enlargeIfNeeded: MethodHandle =
        publicLookup().findStatic(
            coverageMapClass,
            "enlargeIfNeeded",
            methodType(
                Void::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
            ),
        )

    // ── Source location tracking ──────────────────────────────────
    private var sourceFile: String = ""
    private var simpleClassName: String = ""
    private val methodNameList = mutableListOf<String>()
    private val methodNameIndex = mutableMapOf<String, Int>()
    private val locationData = mutableListOf<Int>()

    private fun internMethodName(name: String): Int =
        methodNameIndex.getOrPut(name) {
            methodNameList.add(name)
            methodNameList.size - 1
        }

    /** Returns the collected edge locations, or null if no edges were instrumented. */
    fun buildEdgeLocations(): EdgeLocationData? {
        if (numEdges == 0) return null
        return EdgeLocationData(
            sourceFile,
            methodNameList.toTypedArray(),
            locationData.toIntArray(),
        )
    }

    override fun instrument(
        internalClassName: String,
        bytecode: ByteArray,
    ): ByteArray {
        val lastSlash = internalClassName.lastIndexOf('/')
        simpleClassName = if (lastSlash >= 0) internalClassName.substring(lastSlash + 1) else internalClassName
        // Fallback source file if the class has no SourceFile attribute.
        sourceFile = internalClassName

        val reader = InstrSupport.classReaderFor(bytecode)
        val writer = ClassWriter(reader, 0)
        val version = InstrSupport.getMajorVersion(reader)
        val visitor =
            EdgeCoverageClassProbesAdapter(
                ClassInstrumenter(edgeCoverageProbeArrayStrategy, edgeCoverageProbeInserterFactory, writer),
                InstrSupport.needsFrames(version),
            )
        reader.accept(visitor, ClassReader.EXPAND_FRAMES)
        return writer.toByteArray()
    }

    fun analyze(
        executionData: ExecutionDataStore,
        coverageVisitor: ICoverageVisitor,
        bytecode: ByteArray,
        internalClassName: String,
    ) {
        Analyzer(executionData, coverageVisitor, edgeCoverageClassProbesAdapterFactory).run {
            analyzeClass(bytecode, internalClassName)
        }
    }

    val numEdges
        get() = nextEdgeId - initialEdgeId

    private fun nextEdgeId(): Int {
        enlargeIfNeeded.invokeExact(nextEdgeId)
        return nextEdgeId++
    }

    /**
     * A [ProbeInserter] that injects bytecode instrumentation at every control flow edge and
     * modifies the stack size and number of local variables accordingly.
     *
     * Also records the source location of each probe for PC symbolization.
     */
    private inner class EdgeCoverageProbeInserter(
        access: Int,
        name: String,
        desc: String,
        mv: MethodVisitor,
        arrayStrategy: IProbeArrayStrategy,
    ) : ProbeInserter(access, name, desc, mv, arrayStrategy) {
        private var currentLine = 0
        private var isFirstProbe = true
        private val methodIdx = internMethodName("$simpleClassName.$name")

        override fun visitLineNumber(
            line: Int,
            start: Label,
        ) {
            currentLine = line
            super.visitLineNumber(line, start)
        }

        override fun insertProbe(id: Int) {
            // Pack isFuncEntry into the sign bit of the line number.
            val packedLine = if (isFirstProbe) (currentLine or (1 shl 31)) else currentLine
            locationData.add(packedLine)
            locationData.add(methodIdx)
            isFirstProbe = false

            strategy.instrumentControlFlowEdge(mv, id, variable, coverageMapInternalClassName)
        }

        override fun visitMaxs(
            maxStack: Int,
            maxLocals: Int,
        ) {
            val newMaxStack = max(maxStack + strategy.instrumentControlFlowEdgeStackSize, strategy.loadLocalVariableStackSize)
            // Since JaCoCo 0.8.11, ProbeInserter reserves two local variable slots immediately
            // after the method parameters: a "safety slot" and the probe array itself.
            // See: https://github.com/jacoco/jacoco/commit/1a1db3bc1e51d6320ed8eb7da086ad401aef1ff7
            val newMaxLocals = maxLocals + if (strategy.localVariableType != null) 2 else 0
            mv.visitMaxs(newMaxStack, newMaxLocals)
        }

        override fun getLocalVariableType() = strategy.localVariableType
    }

    private val edgeCoverageProbeInserterFactory =
        IProbeInserterFactory { access, name, desc, mv, arrayStrategy ->
            EdgeCoverageProbeInserter(access, name, desc, mv, arrayStrategy)
        }

    private inner class EdgeCoverageClassProbesAdapter(
        private val cpv: ClassProbesVisitor,
        trackFrames: Boolean,
    ) : ClassProbesAdapter(cpv, trackFrames) {
        override fun nextId(): Int = nextEdgeId()

        override fun visitSource(
            source: String?,
            debug: String?,
        ) {
            if (source != null) {
                // sourceFile was initialized to the internal class name (e.g. "com/example/Outer$Inner")
                // in instrument().  Extract the package prefix and prepend it to the declared source
                // file name, giving e.g. "com/example/Outer.java".
                val packageEnd = sourceFile.lastIndexOf('/')
                sourceFile = if (packageEnd >= 0) sourceFile.substring(0, packageEnd + 1) + source else source
            }
            super.visitSource(source, debug)
        }

        override fun visitEnd() {
            cpv.visitTotalProbeCount(numEdges)
            // Avoid calling super.visitEnd() as that invokes cpv.visitTotalProbeCount with an
            // incorrect value of `count`.
            cpv.visitEnd()
        }
    }

    private val edgeCoverageClassProbesAdapterFactory =
        IClassProbesAdapterFactory { probesVisitor, trackFrames ->
            EdgeCoverageClassProbesAdapter(probesVisitor, trackFrames)
        }

    private val edgeCoverageProbeArrayStrategy =
        object : IProbeArrayStrategy {
            override fun storeInstance(
                mv: MethodVisitor,
                clinit: Boolean,
                variable: Int,
            ): Int {
                strategy.loadLocalVariable(mv, variable, coverageMapInternalClassName)
                return strategy.loadLocalVariableStackSize
            }

            override fun addMembers(
                cv: ClassVisitor,
                probeCount: Int,
            ) {}
        }
}

fun MethodVisitor.push(value: Int) {
    InstrSupport.push(this, value)
}
