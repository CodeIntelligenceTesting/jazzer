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

fun extractClassFileMajorVersion(classfileBuffer: ByteArray): Int {
    return ((classfileBuffer[6].toInt() and 0xff) shl 8) or (classfileBuffer[7].toInt() and 0xff)
}

class ClassInstrumentor constructor(bytecode: ByteArray) {

    var instrumentedBytecode = bytecode
        private set

    fun coverage(initialEdgeId: Int): Int {
        val edgeCoverageInstrumentor = EdgeCoverageInstrumentor(initialEdgeId)
        instrumentedBytecode = edgeCoverageInstrumentor.instrument(instrumentedBytecode)
        return edgeCoverageInstrumentor.numEdges
    }

    fun traceDataFlow(instrumentations: Set<InstrumentationType>) {
        instrumentedBytecode = TraceDataFlowInstrumentor(instrumentations).instrument(instrumentedBytecode)
    }

    fun hooks(hooks: Iterable<Hook>) {
        instrumentedBytecode = HookInstrumentor(
            hooks,
            java6Mode = extractClassFileMajorVersion(instrumentedBytecode) < 51
        ).instrument(instrumentedBytecode)
    }

    companion object {
        init {
            try {
                // Calls JNI_OnLoad_jazzer_initialize in the driver, which registers the native methods.
                System.loadLibrary("jazzer_initialize")
            } catch (_: UnsatisfiedLinkError) {
                // Make it possible to use (parts of) the agent without the driver.
            }
        }
    }
}
