/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor

internal class HookInstrumentor(
    private val hooks: Iterable<Hook>,
    private val java6Mode: Boolean,
    private val classWithHooksEnabledField: String?,
) : Instrumentor {

    private lateinit var random: DeterministicRandom

    override fun instrument(internalClassName: String, bytecode: ByteArray): ByteArray {
        val reader = ClassReader(bytecode)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
        random = DeterministicRandom("hook", reader.className)
        val interceptor = object : ClassVisitor(Instrumentor.ASM_API_VERSION, writer) {
            override fun visitMethod(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                val mv = cv.visitMethod(access, name, descriptor, signature, exceptions) ?: return null
                return if (shouldInstrument(access)) {
                    makeHookMethodVisitor(
                        internalClassName,
                        access,
                        name,
                        descriptor,
                        mv,
                        hooks,
                        java6Mode,
                        random,
                        classWithHooksEnabledField,
                    )
                } else {
                    mv
                }
            }
        }
        reader.accept(interceptor, ClassReader.EXPAND_FRAMES)
        return writer.toByteArray()
    }
}
