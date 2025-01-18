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
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.VarInsnNode

internal class TraceDataFlowInstrumentor(
    private val types: Set<InstrumentationType>,
    private val callbackInternalClassName: String = "com/code_intelligence/jazzer/runtime/TraceDataFlowNativeCallbacks",
) : Instrumentor {
    private lateinit var random: DeterministicRandom

    override fun instrument(
        internalClassName: String,
        bytecode: ByteArray,
    ): ByteArray {
        val node = ClassNode()
        val reader = ClassReader(bytecode)
        reader.accept(node, 0)
        random = DeterministicRandom("trace", node.name)
        for (method in node.methods) {
            if (shouldInstrument(method)) {
                addDataFlowInstrumentation(method)
            }
        }

        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        node.accept(writer)
        return writer.toByteArray()
    }

    private fun addDataFlowInstrumentation(method: MethodNode) {
        loop@ for (inst in method.instructions.toArray()) {
            when (inst.opcode) {
                Opcodes.LCMP -> {
                    if (InstrumentationType.CMP !in types) continue@loop
                    method.instructions.insertBefore(inst, longCmpInstrumentation())
                    method.instructions.remove(inst)
                }
                Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE,
                Opcodes.IF_ICMPLT, Opcodes.IF_ICMPLE,
                Opcodes.IF_ICMPGT, Opcodes.IF_ICMPGE,
                -> {
                    if (InstrumentationType.CMP !in types) continue@loop
                    method.instructions.insertBefore(inst, intCmpInstrumentation())
                }
                Opcodes.IFEQ, Opcodes.IFNE,
                Opcodes.IFLT, Opcodes.IFLE,
                Opcodes.IFGT, Opcodes.IFGE,
                -> {
                    if (InstrumentationType.CMP !in types) continue@loop
                    // The IF* opcodes are often used to branch based on the result of a compare
                    // instruction for a type other than int. The operands of this compare will
                    // already be reported via the instrumentation above (for non-floating point
                    // numbers) and the follow-up compare does not provide a good signal as all
                    // operands will be in {-1, 0, 1}. Skip instrumentation for it.
                    if (inst.previous?.opcode in listOf(Opcodes.DCMPG, Opcodes.DCMPL, Opcodes.FCMPG, Opcodes.DCMPL) ||
                        (inst.previous as? MethodInsnNode)?.name == "traceCmpLongWrapper"
                    ) {
                        continue@loop
                    }
                    method.instructions.insertBefore(inst, ifInstrumentation())
                }
                Opcodes.LOOKUPSWITCH, Opcodes.TABLESWITCH -> {
                    if (InstrumentationType.CMP !in types) continue@loop
                    // Mimic the exclusion logic for small label values in libFuzzer:
                    // https://github.com/llvm-mirror/compiler-rt/blob/69445f095c22aac2388f939bedebf224a6efcdaf/lib/fuzzer/FuzzerTracePC.cpp#L520
                    // Case values are reported to libFuzzer via an array of unsigned long values and thus need to be
                    // sorted by unsigned value.
                    val caseValues =
                        when (inst) {
                            is LookupSwitchInsnNode -> {
                                // If the switch is over String values, find out the actual values and not the hashes, and
                                // report them to libFuzzer in the switch's default case.
                                if (instrumentSwitchOverStrings(method, inst)) {
                                    continue@loop
                                }
                                if (inst.keys.isEmpty() || (0 <= inst.keys.first() && inst.keys.last() < 256)) {
                                    continue@loop
                                }
                                inst.keys
                            }
                            is TableSwitchInsnNode -> {
                                if (0 <= inst.min && inst.max < 256) {
                                    continue@loop
                                }
                                (inst.min..inst.max)
                                    .filter { caseValue ->
                                        val index = caseValue - inst.min
                                        // Filter out "gap cases".
                                        inst.labels[index].label != inst.dflt.label
                                    }.toList()
                            }
                            // Not reached.
                            else -> continue@loop
                        }.sortedBy { it.toUInt() }.map { it.toLong() }.toLongArray()
                    method.instructions.insertBefore(inst, switchInstrumentation(caseValues))
                }
                Opcodes.IDIV -> {
                    if (InstrumentationType.DIV !in types) continue@loop
                    method.instructions.insertBefore(inst, intDivInstrumentation())
                }
                Opcodes.LDIV -> {
                    if (InstrumentationType.DIV !in types) continue@loop
                    method.instructions.insertBefore(inst, longDivInstrumentation())
                }
                Opcodes.AALOAD, Opcodes.BALOAD,
                Opcodes.CALOAD, Opcodes.DALOAD,
                Opcodes.FALOAD, Opcodes.IALOAD,
                Opcodes.LALOAD, Opcodes.SALOAD,
                -> {
                    if (InstrumentationType.GEP !in types) continue@loop
                    if (!isConstantIntegerPushInsn(inst.previous)) continue@loop
                    method.instructions.insertBefore(inst, gepLoadInstrumentation())
                }
                Opcodes.INVOKEINTERFACE, Opcodes.INVOKESPECIAL, Opcodes.INVOKESTATIC, Opcodes.INVOKEVIRTUAL -> {
                    if (InstrumentationType.GEP !in types) continue@loop
                    if (!isGepLoadMethodInsn(inst as MethodInsnNode)) continue@loop
                    if (!isConstantIntegerPushInsn(inst.previous)) continue@loop
                    method.instructions.insertBefore(inst, gepLoadInstrumentation())
                }
            }
        }
    }

    /**
     * Instruments a switch instruction over Strings to report the actual values to libFuzzer.
     * Return true if the instrumentation was successful.
     * TODO: this might stop working if we add instrumentation to e.g. hashCode method.
     *       Can the switch be instrumented in a more generic way?
     */
    private fun instrumentSwitchOverStrings(
        method: MethodNode,
        switchInsn: LookupSwitchInsnNode,
    ): Boolean {
        val hashCodeCall: AbstractInsnNode = switchInsn.previous
        when (hashCodeCall) {
            is MethodInsnNode -> {
                if (hashCodeCall.name != "hashCode") {
                    return false
                }
                if (hashCodeCall.owner != "java/lang/String") {
                    return false
                }
            }
            else -> {
                return false
            }
        }
        // Copy the variable from ALOAD instruction before the hashCode call
        val query = hashCodeCall.previous
        val variableN = (query as? VarInsnNode)?.`var` ?: return false

        // So far, it seems that there is always a default label present.
        val defaultLabel = switchInsn.dflt ?: return false
        val labels = switchInsn.labels ?: return false

        // Extract the string values from the LDC instructions for each label in the switch.
        val cases = mutableListOf<String>()
        for (label in labels) {
            if (label !is LabelNode) {
                continue
            }
            var current: AbstractInsnNode = label
            while (true) {
                current = current.next
                // lookupswitch compares the keys to the actual values after the initial equality check of the hash codes
                when (current) {
                    is LdcInsnNode -> {
                        if (current.cst is String) {
                            cases.add(current.cst as String)
                        }
                        break
                    }
                }
            }
        }

        // Given a switch on a string:
        // switch(str) {
        //   case "foo": ...
        //   case "bar": ...
        //   default: ...
        // }
        // We change it to:
        // switch(str) {
        //   case "foo": ...
        //   case "bar": ...
        //   default:
        //     str.equals("foo");
        //     str.equals("bar");
        //     ...
        // }
        val instrumentationBlock = InsnList()
        // load the switch variable to the stack
        instrumentationBlock.add(VarInsnNode(Opcodes.ALOAD, variableN))
        cases.forEach {
            // duplicate the switch variable
            instrumentationBlock.add(InsnNode(Opcodes.DUP))
            // load the string constant to the stack
            instrumentationBlock.add(LdcInsnNode(it))
            // call the equals method on the switch variable with the string constant as argument
            instrumentationBlock.add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false))
            // pop the result of the equals method from stack
            instrumentationBlock.add(InsnNode(Opcodes.POP))
        }
        // pop the switch variable from stack
        instrumentationBlock.add(InsnNode(Opcodes.POP))
        // insert the new instructions after the frame node that follows the default label bytecode instruction
        // F_NEW LNNNNN... ;; default label
        // F_NEW: FRAME([java/lang/String, 1]) - null
        if (defaultLabel.next != null) {
            method.instructions.insert(defaultLabel.next, instrumentationBlock)
            return true
        }
        return false
    }

    private fun InsnList.pushFakePc() {
        add(LdcInsnNode(random.nextInt(512)))
    }

    private fun longCmpInstrumentation() =
        InsnList().apply {
            pushFakePc()
            // traceCmpLong returns the result of the comparison as duplicating two longs on the stack
            // is not possible without local variables.
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceCmpLongWrapper", "(JJI)I", false))
        }

    private fun intCmpInstrumentation() =
        InsnList().apply {
            add(InsnNode(Opcodes.DUP2))
            pushFakePc()
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceCmpInt", "(III)V", false))
        }

    private fun ifInstrumentation() =
        InsnList().apply {
            add(InsnNode(Opcodes.DUP))
            // All if* instructions are compares to the constant 0.
            add(InsnNode(Opcodes.ICONST_0))
            add(InsnNode(Opcodes.SWAP))
            pushFakePc()
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceConstCmpInt", "(III)V", false))
        }

    private fun intDivInstrumentation() =
        InsnList().apply {
            add(InsnNode(Opcodes.DUP))
            pushFakePc()
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceDivInt", "(II)V", false))
        }

    private fun longDivInstrumentation() =
        InsnList().apply {
            add(InsnNode(Opcodes.DUP2))
            pushFakePc()
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceDivLong", "(JI)V", false))
        }

    private fun switchInstrumentation(caseValues: LongArray) =
        InsnList().apply {
            // duplicate {lookup,table}switch key for use as first function argument
            add(InsnNode(Opcodes.DUP))
            add(InsnNode(Opcodes.I2L))
            // Set up array with switch case values. The format libfuzzer expects is created here directly, i.e., the first
            // two entries are the number of cases and the bit size of values (always 32).
            add(IntInsnNode(Opcodes.SIPUSH, caseValues.size + 2))
            add(IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG))
            // Store number of cases
            add(InsnNode(Opcodes.DUP))
            add(IntInsnNode(Opcodes.SIPUSH, 0))
            add(LdcInsnNode(caseValues.size.toLong()))
            add(InsnNode(Opcodes.LASTORE))
            // Store bit size of keys
            add(InsnNode(Opcodes.DUP))
            add(IntInsnNode(Opcodes.SIPUSH, 1))
            add(LdcInsnNode(32.toLong()))
            add(InsnNode(Opcodes.LASTORE))
            // Store {lookup,table}switch case values
            for ((i, caseValue) in caseValues.withIndex()) {
                add(InsnNode(Opcodes.DUP))
                add(IntInsnNode(Opcodes.SIPUSH, 2 + i))
                add(LdcInsnNode(caseValue))
                add(InsnNode(Opcodes.LASTORE))
            }
            pushFakePc()
            // call the native callback function
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceSwitch", "(J[JI)V", false))
        }

    /**
     * Returns true if [node] represents an instruction that possibly pushes a valid, non-zero, constant array index
     * onto the stack.
     */
    private fun isConstantIntegerPushInsn(node: AbstractInsnNode?) = node?.opcode in CONSTANT_INTEGER_PUSH_OPCODES

    /**
     * Returns true if [node] represents a call to a method that performs an indexed lookup into an array-like
     * structure.
     */
    private fun isGepLoadMethodInsn(node: MethodInsnNode): Boolean {
        if (!node.desc.startsWith("(I)")) return false
        val returnType = node.desc.removePrefix("(I)")
        return MethodInfo(node.owner, node.name, returnType) in GEP_LOAD_METHODS
    }

    private fun gepLoadInstrumentation() =
        InsnList().apply {
            // Duplicate the index and convert to long.
            add(InsnNode(Opcodes.DUP))
            add(InsnNode(Opcodes.I2L))
            pushFakePc()
            add(MethodInsnNode(Opcodes.INVOKESTATIC, callbackInternalClassName, "traceGep", "(JI)V", false))
        }

    companion object {
        // Low constants (0, 1) are omitted as they create a lot of noise.
        val CONSTANT_INTEGER_PUSH_OPCODES =
            listOf(
                Opcodes.BIPUSH,
                Opcodes.SIPUSH,
                Opcodes.LDC,
                Opcodes.ICONST_2,
                Opcodes.ICONST_3,
                Opcodes.ICONST_4,
                Opcodes.ICONST_5,
            )

        data class MethodInfo(
            val internalClassName: String,
            val name: String,
            val returnType: String,
        )

        val GEP_LOAD_METHODS =
            setOf(
                MethodInfo("java/util/AbstractList", "get", "Ljava/lang/Object;"),
                MethodInfo("java/util/ArrayList", "get", "Ljava/lang/Object;"),
                MethodInfo("java/util/List", "get", "Ljava/lang/Object;"),
                MethodInfo("java/util/Stack", "get", "Ljava/lang/Object;"),
                MethodInfo("java/util/Vector", "get", "Ljava/lang/Object;"),
                MethodInfo("java/lang/CharSequence", "charAt", "C"),
                MethodInfo("java/lang/String", "charAt", "C"),
                MethodInfo("java/lang/StringBuffer", "charAt", "C"),
                MethodInfo("java/lang/StringBuilder", "charAt", "C"),
                MethodInfo("java/lang/String", "codePointAt", "I"),
                MethodInfo("java/lang/String", "codePointBefore", "I"),
                MethodInfo("java/nio/ByteBuffer", "get", "B"),
                MethodInfo("java/nio/ByteBuffer", "getChar", "C"),
                MethodInfo("java/nio/ByteBuffer", "getDouble", "D"),
                MethodInfo("java/nio/ByteBuffer", "getFloat", "F"),
                MethodInfo("java/nio/ByteBuffer", "getInt", "I"),
                MethodInfo("java/nio/ByteBuffer", "getLong", "J"),
                MethodInfo("java/nio/ByteBuffer", "getShort", "S"),
            )
    }
}
