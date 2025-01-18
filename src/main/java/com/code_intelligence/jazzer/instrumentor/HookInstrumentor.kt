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

    override fun instrument(
        internalClassName: String,
        bytecode: ByteArray,
    ): ByteArray {
        val reader = ClassReader(bytecode)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
        random = DeterministicRandom("hook", reader.className)
        val interceptor =
            object : ClassVisitor(Instrumentor.ASM_API_VERSION, writer) {
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
