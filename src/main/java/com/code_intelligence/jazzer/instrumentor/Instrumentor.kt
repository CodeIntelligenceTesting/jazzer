/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
    fun instrument(internalClassName: String, bytecode: ByteArray): ByteArray

    fun shouldInstrument(access: Int): Boolean {
        return (access and Opcodes.ACC_ABSTRACT == 0) &&
            (access and Opcodes.ACC_NATIVE == 0)
    }

    fun shouldInstrument(method: MethodNode): Boolean {
        return shouldInstrument(method.access) &&
            method.instructions.size() > 0
    }

    companion object {
        const val ASM_API_VERSION = Opcodes.ASM9
    }
}
