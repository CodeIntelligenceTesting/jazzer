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

import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.MethodNode

enum class InstrumentationType {
    CMP,
    COV,
    DIV,
    GEP,
    INDIR,
    NATIVE,
}

internal interface Instrumentor {
    fun instrument(
        internalClassName: String,
        bytecode: ByteArray,
    ): ByteArray

    fun shouldInstrument(access: Int): Boolean =
        (access and Opcodes.ACC_ABSTRACT == 0) &&
            (access and Opcodes.ACC_NATIVE == 0)

    fun shouldInstrument(method: MethodNode): Boolean =
        shouldInstrument(method.access) &&
            method.instructions.size() > 0

    companion object {
        const val ASM_API_VERSION = Opcodes.ASM9
    }
}
