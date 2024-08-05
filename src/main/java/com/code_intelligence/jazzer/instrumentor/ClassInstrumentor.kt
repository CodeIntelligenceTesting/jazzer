/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor

import com.code_intelligence.jazzer.runtime.CoverageMap

fun extractClassFileMajorVersion(classfileBuffer: ByteArray): Int {
    return ((classfileBuffer[6].toInt() and 0xff) shl 8) or (classfileBuffer[7].toInt() and 0xff)
}

class ClassInstrumentor(private val internalClassName: String, bytecode: ByteArray) {

    var instrumentedBytecode = bytecode
        private set

    fun coverage(initialEdgeId: Int): Int {
        val edgeCoverageInstrumentor = EdgeCoverageInstrumentor(
            defaultEdgeCoverageStrategy,
            defaultCoverageMap,
            initialEdgeId,
        )
        instrumentedBytecode = edgeCoverageInstrumentor.instrument(internalClassName, instrumentedBytecode)
        return edgeCoverageInstrumentor.numEdges
    }

    fun traceDataFlow(instrumentations: Set<InstrumentationType>) {
        instrumentedBytecode =
            TraceDataFlowInstrumentor(instrumentations).instrument(internalClassName, instrumentedBytecode)
    }

    fun hooks(hooks: Iterable<Hook>, classWithHooksEnabledField: String?) {
        instrumentedBytecode = HookInstrumentor(
            hooks,
            java6Mode = extractClassFileMajorVersion(instrumentedBytecode) < 51,
            classWithHooksEnabledField = classWithHooksEnabledField,
        ).instrument(internalClassName, instrumentedBytecode)
    }

    companion object {
        val defaultEdgeCoverageStrategy = StaticMethodStrategy()
        val defaultCoverageMap = CoverageMap::class.java
    }
}
