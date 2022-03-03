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

import com.code_intelligence.jazzer.api.HookType
import org.objectweb.asm.Handle
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.commons.LocalVariablesSorter
import java.util.concurrent.atomic.AtomicBoolean

internal fun makeHookMethodVisitor(
    access: Int,
    descriptor: String?,
    methodVisitor: MethodVisitor?,
    hooks: Iterable<Hook>,
    java6Mode: Boolean,
    random: DeterministicRandom,
): MethodVisitor {
    return HookMethodVisitor(access, descriptor, methodVisitor, hooks, java6Mode, random).lvs
}

private class HookMethodVisitor(
    access: Int,
    descriptor: String?,
    methodVisitor: MethodVisitor?,
    hooks: Iterable<Hook>,
    private val java6Mode: Boolean,
    private val random: DeterministicRandom,
) : MethodVisitor(Instrumentor.ASM_API_VERSION, methodVisitor) {

    companion object {
        private val showUnsupportedHookWarning = AtomicBoolean(true)
    }

    val lvs = object : LocalVariablesSorter(Instrumentor.ASM_API_VERSION, access, descriptor, this) {
        override fun updateNewLocals(newLocals: Array<Any>) {
            // The local variables involved in calling hooks do not need to outlive the current
            // basic block and should thus not appear in stack map frames. By requesting the
            // LocalVariableSorter to fill their entries in stack map frames with TOP, they will
            // be treated like an unused local variable slot.
            newLocals.fill(Opcodes.TOP)
        }
    }

    private val hooks = hooks.associateBy { hook ->
        var hookKey = "${hook.hookType}#${hook.targetInternalClassName}#${hook.targetMethodName}"
        if (hook.targetMethodDescriptor != null)
            hookKey += "#${hook.targetMethodDescriptor}"
        hookKey
    }

    override fun visitMethodInsn(
        opcode: Int,
        owner: String,
        methodName: String,
        methodDescriptor: String,
        isInterface: Boolean,
    ) {
        if (!isMethodInvocationOp(opcode)) {
            mv.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
            return
        }
        handleMethodInsn(HookType.BEFORE, opcode, owner, methodName, methodDescriptor, isInterface)
    }

    /**
     * Emits the bytecode for a method call instruction for the next applicable hook type in order (BEFORE, REPLACE,
     * AFTER). Since the instrumented code is indistinguishable from an uninstrumented call instruction, it can be
     * safely nested. Combining REPLACE hooks with other hooks is however not supported as these hooks already subsume
     * the functionality of BEFORE and AFTER hooks.
     */
    private fun visitNextHookTypeOrCall(
        hookType: HookType,
        appliedHook: Boolean,
        opcode: Int,
        owner: String,
        methodName: String,
        methodDescriptor: String,
        isInterface: Boolean,
    ) = when (hookType) {
        HookType.BEFORE -> {
            val nextHookType = if (appliedHook) {
                // After a BEFORE hook has been applied, we can safely apply an AFTER hook by replacing the actual
                // call instruction with the full bytecode injected for the AFTER hook.
                HookType.AFTER
            } else {
                // If no BEFORE hook is registered, look for a REPLACE hook next.
                HookType.REPLACE
            }
            handleMethodInsn(nextHookType, opcode, owner, methodName, methodDescriptor, isInterface)
        }
        HookType.REPLACE -> {
            // REPLACE hooks can't (and don't need to) be mixed with other hooks. We only cycle through them if we
            // couldn't find a matching REPLACE hook, in which case we try an AFTER hook next.
            require(!appliedHook)
            handleMethodInsn(HookType.AFTER, opcode, owner, methodName, methodDescriptor, isInterface)
        }
        // An AFTER hook is always the last in the chain. Whether a hook has been applied or not, always emit the
        // actual call instruction.
        HookType.AFTER -> mv.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
    }

    fun handleMethodInsn(
        hookType: HookType,
        opcode: Int,
        owner: String,
        methodName: String,
        methodDescriptor: String,
        isInterface: Boolean,
    ) {
        val hook = findMatchingHook(hookType, owner, methodName, methodDescriptor)
        if (hook == null) {
            visitNextHookTypeOrCall(hookType, false, opcode, owner, methodName, methodDescriptor, isInterface)
            return
        }

        if (java6Mode && hookType == HookType.REPLACE) {
            if (showUnsupportedHookWarning.getAndSet(false)) {
                println(
                    """WARN: Some hooks could not be applied to class files built for Java 7 or lower.
                      |WARN: Ensure that the fuzz target and its dependencies are compiled with
                      |WARN: -target 8 or higher to identify as many bugs as possible.
            """.trimMargin()
                )
            }
            visitNextHookTypeOrCall(hookType, false, opcode, owner, methodName, methodDescriptor, isInterface)
            return
        }

        // The hookId is used to identify a call site.
        val hookId = random.nextInt()

        val paramDescriptors = extractParameterTypeDescriptors(methodDescriptor)
        val localObjArr = storeMethodArguments(paramDescriptors)
        // If the method we're hooking is not static there is now a reference to
        // the object the method was invoked on at the top of the stack.
        // If the method is static, that object is missing. We make up for it by pushing a null ref.
        if (opcode == Opcodes.INVOKESTATIC) {
            mv.visitInsn(Opcodes.ACONST_NULL)
        }

        // Save the owner object to a new local variable
        val ownerDescriptor = "L$owner;"
        val localOwnerObj = lvs.newLocal(Type.getType(ownerDescriptor))
        mv.visitVarInsn(Opcodes.ASTORE, localOwnerObj) // consume objectref
        // We now removed all values for the original method call from the operand stack
        // and saved them to local variables.

        // Start to build the arguments for the hook method.
        if (methodName == "<init>") {
            // Constructor is invoked on an uninitialized object, and that's still on the stack.
            // In case of REPLACE pop it from the stack and replace it afterwards with the returned
            // one from the hook.
            if (hook.hookType == HookType.REPLACE) {
                mv.visitInsn(Opcodes.POP)
            }
            // Special case for constructors:
            // We cannot create a MethodHandle for a constructor, so we push null instead.
            mv.visitInsn(Opcodes.ACONST_NULL) // push nullref
            // Only pass the this object if it has been initialized by the time the hook is invoked.
            if (hook.hookType == HookType.AFTER) {
                mv.visitVarInsn(Opcodes.ALOAD, localOwnerObj)
            } else {
                mv.visitInsn(Opcodes.ACONST_NULL) // push nullref
            }
        } else {
            // Push a MethodHandle representing the hooked method.
            val handleOpcode = when (opcode) {
                Opcodes.INVOKEVIRTUAL -> Opcodes.H_INVOKEVIRTUAL
                Opcodes.INVOKEINTERFACE -> Opcodes.H_INVOKEINTERFACE
                Opcodes.INVOKESTATIC -> Opcodes.H_INVOKESTATIC
                Opcodes.INVOKESPECIAL -> Opcodes.H_INVOKESPECIAL
                else -> -1
            }
            if (java6Mode) {
                // MethodHandle constants (type 15) are not supported in Java 6 class files (major version 50).
                mv.visitInsn(Opcodes.ACONST_NULL) // push nullref
            } else {
                mv.visitLdcInsn(
                    Handle(
                        handleOpcode,
                        owner,
                        methodName,
                        methodDescriptor,
                        isInterface
                    )
                ) // push MethodHandle
            }
            // Stack layout: ... | MethodHandle (objectref)
            // Push the owner object again
            mv.visitVarInsn(Opcodes.ALOAD, localOwnerObj)
        }
        // Stack layout: ... | MethodHandle (objectref) | owner (objectref)
        // Push a reference to our object array with the saved arguments
        mv.visitVarInsn(Opcodes.ALOAD, localObjArr)
        // Stack layout: ... | MethodHandle (objectref) | owner (objectref) | object array (arrayref)
        // Push the hook id
        mv.visitLdcInsn(hookId)
        // Stack layout: ... | MethodHandle (objectref) | owner (objectref) | object array (arrayref) | hookId (int)
        // How we proceed depends on the type of hook we want to implement
        when (hook.hookType) {
            HookType.BEFORE -> {
                // Call the hook method
                mv.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    hook.hookInternalClassName,
                    hook.hookMethodName,
                    hook.hookMethodDescriptor,
                    false
                )
                // Stack layout: ...
                // Push the values for the original method call onto the stack again
                if (opcode != Opcodes.INVOKESTATIC) {
                    mv.visitVarInsn(Opcodes.ALOAD, localOwnerObj) // push owner object
                }
                loadMethodArguments(paramDescriptors, localObjArr) // push all method arguments
                // Stack layout: ... | [owner (objectref)] | arg1 (primitive/objectref) | arg2 (primitive/objectref) | ...
                // Call the original method or the next hook in order.
                visitNextHookTypeOrCall(hookType, true, opcode, owner, methodName, methodDescriptor, isInterface)
            }
            HookType.REPLACE -> {
                // Call the hook method
                mv.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    hook.hookInternalClassName,
                    hook.hookMethodName,
                    hook.hookMethodDescriptor,
                    false
                )
                // Stack layout: ... | [return value (primitive/objectref)]
                // Check if we need to process the return value
                val returnTypeDescriptor = extractReturnTypeDescriptor(methodDescriptor)
                if (returnTypeDescriptor != "V") {
                    val hookMethodReturnType = extractReturnTypeDescriptor(hook.hookMethodDescriptor)
                    // if the hook method's return type is primitive we don't need to unwrap or cast it
                    if (!isPrimitiveType(hookMethodReturnType)) {
                        // Check if the returned object type is different than the one that should be returned
                        // If a primitive should be returned we check it's wrapper type
                        val expectedType = getWrapperTypeDescriptor(returnTypeDescriptor)
                        if (expectedType != hookMethodReturnType) {
                            // Cast object
                            mv.visitTypeInsn(Opcodes.CHECKCAST, extractInternalClassName(expectedType))
                        }
                        // Check if we need to unwrap the returned object
                        unwrapTypeIfPrimitive(returnTypeDescriptor)
                    }
                }
            }
            HookType.AFTER -> {
                // Push the values for the original method call again onto the stack
                if (opcode != Opcodes.INVOKESTATIC) {
                    mv.visitVarInsn(Opcodes.ALOAD, localOwnerObj) // push owner object
                }
                loadMethodArguments(paramDescriptors, localObjArr) // push all method arguments
                // Stack layout: ... | MethodHandle (objectref) | owner (objectref) | object array (arrayref) | hookId (int)
                //                   | [owner (objectref)] | arg1 (primitive/objectref) | arg2 (primitive/objectref) | ...
                // Call the original method or the next hook in order
                visitNextHookTypeOrCall(hookType, true, opcode, owner, methodName, methodDescriptor, isInterface)
                val returnTypeDescriptor = extractReturnTypeDescriptor(methodDescriptor)
                if (returnTypeDescriptor == "V") {
                    // If the method didn't return anything, we push a nullref as placeholder
                    mv.visitInsn(Opcodes.ACONST_NULL) // push nullref
                }
                // Wrap return value if it is a primitive type
                wrapTypeIfPrimitive(returnTypeDescriptor)
                // Stack layout: ... | MethodHandle (objectref) | owner (objectref) | object array (arrayref) | hookId (int)
                //                   | return value (objectref)
                // Store the result value in a local variable (but keep it on the stack)
                val localReturnObj = lvs.newLocal(Type.getType(getWrapperTypeDescriptor(returnTypeDescriptor)))
                mv.visitVarInsn(Opcodes.ASTORE, localReturnObj) // consume objectref
                mv.visitVarInsn(Opcodes.ALOAD, localReturnObj) // push objectref
                // Call the hook method
                mv.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    hook.hookInternalClassName,
                    hook.hookMethodName,
                    hook.hookMethodDescriptor,
                    false
                )
                // Stack layout: ...
                if (returnTypeDescriptor != "V") {
                    // Push the return value again
                    mv.visitVarInsn(Opcodes.ALOAD, localReturnObj) // push objectref
                    // Unwrap it, if it was a primitive value
                    unwrapTypeIfPrimitive(returnTypeDescriptor)
                    // Stack layout: ... | return value (primitive/objectref)
                }
            }
        }
    }

    private fun isMethodInvocationOp(opcode: Int) = opcode in listOf(
        Opcodes.INVOKEVIRTUAL,
        Opcodes.INVOKEINTERFACE,
        Opcodes.INVOKESTATIC,
        Opcodes.INVOKESPECIAL
    )

    private fun findMatchingHook(hookType: HookType, owner: String, name: String, descriptor: String): Hook? {
        val withoutDescriptorKey = "$hookType#$owner#$name"
        val withDescriptorKey = "$withoutDescriptorKey#$descriptor"
        return hooks[withDescriptorKey] ?: hooks[withoutDescriptorKey]
    }

    // Stores all arguments for a method call in a local object array.
    // paramDescriptors: The type descriptors for all method arguments
    private fun storeMethodArguments(paramDescriptors: List<String>): Int {
        // Allocate a new Object[] for the methods parameters.
        mv.visitIntInsn(Opcodes.SIPUSH, paramDescriptors.size)
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")
        val localObjArr = lvs.newLocal(Type.getType("[Ljava/lang/Object;"))
        mv.visitVarInsn(Opcodes.ASTORE, localObjArr)

        // Loop over all arguments in reverse order (because the last argument is on top).
        for ((argIdx, argDescriptor) in paramDescriptors.withIndex().reversed()) {
            // If the argument is a primitive type, wrap it in it's wrapper class
            wrapTypeIfPrimitive(argDescriptor)
            // Store the argument in our object array, for that we need to shape the stack first.
            // Stack layout: ... | method argument (objectref)
            mv.visitVarInsn(Opcodes.ALOAD, localObjArr)
            // Stack layout: ... | method argument (objectref) | object array (arrayref)
            mv.visitInsn(Opcodes.SWAP)
            // Stack layout: ... | object array (arrayref) | method argument (objectref)
            mv.visitIntInsn(Opcodes.SIPUSH, argIdx)
            // Stack layout: ... | object array (arrayref) | method argument (objectref) | argument index (int)
            mv.visitInsn(Opcodes.SWAP)
            // Stack layout: ... | object array (arrayref) | argument index (int) | method argument (objectref)
            mv.visitInsn(Opcodes.AASTORE) // consume all three: arrayref, index, value
            // Stack layout: ...
            // Continue with the remaining method arguments
        }

        // Return a reference to the array with the parameters.
        return localObjArr
    }

    // Loads all arguments for a method call from a local object array.
    // argTypeSigs: The type signatures for all method arguments
    // localObjArr: Index of a local variable containing an object array where the arguments will be loaded from
    private fun loadMethodArguments(paramDescriptors: List<String>, localObjArr: Int) {
        // Loop over all arguments
        for ((argIdx, argDescriptor) in paramDescriptors.withIndex()) {
            // Push a reference to the object array on the stack
            mv.visitVarInsn(Opcodes.ALOAD, localObjArr)
            // Stack layout: ... | object array (arrayref)
            // Push the index of the current argument on the stack
            mv.visitIntInsn(Opcodes.SIPUSH, argIdx)
            // Stack layout: ... | object array (arrayref) | argument index (int)
            // Load the argument from the array
            mv.visitInsn(Opcodes.AALOAD)
            // Stack layout: ... | method argument (objectref)
            // Cast object to it's original type (or it's wrapper object)
            val wrapperTypeDescriptor = getWrapperTypeDescriptor(argDescriptor)
            mv.visitTypeInsn(Opcodes.CHECKCAST, extractInternalClassName(wrapperTypeDescriptor))
            // If the argument is a supposed to be a primitive type, unwrap the wrapped type
            unwrapTypeIfPrimitive(argDescriptor)
            // Stack layout: ... | method argument (primitive/objectref)
            // Continue with the remaining method arguments
        }
    }

    // Removes a primitive value from the top of the operand stack
    // and pushes it enclosed in it's wrapper type (e.g. removes int, pushes Integer).
    // This is done by calling .valueOf(...) on the wrapper class.
    private fun wrapTypeIfPrimitive(unwrappedTypeDescriptor: String) {
        if (!isPrimitiveType(unwrappedTypeDescriptor) || unwrappedTypeDescriptor == "V") return
        val wrapperTypeDescriptor = getWrapperTypeDescriptor(unwrappedTypeDescriptor)
        val wrapperType = extractInternalClassName(wrapperTypeDescriptor)
        val valueOfDescriptor = "($unwrappedTypeDescriptor)$wrapperTypeDescriptor"
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, wrapperType, "valueOf", valueOfDescriptor, false)
    }

    // Removes a wrapper object around a given primitive type from the top of the operand stack
    // and pushes the primitive value it contains (e.g. removes Integer, pushes int).
    // This is done by calling .intValue(...) / .charValue(...) / ... on the wrapper object.
    private fun unwrapTypeIfPrimitive(primitiveTypeDescriptor: String) {
        val (methodName, wrappedTypeDescriptor) = when (primitiveTypeDescriptor) {
            "B" -> Pair("byteValue", "java/lang/Byte")
            "C" -> Pair("charValue", "java/lang/Character")
            "D" -> Pair("doubleValue", "java/lang/Double")
            "F" -> Pair("floatValue", "java/lang/Float")
            "I" -> Pair("intValue", "java/lang/Integer")
            "J" -> Pair("longValue", "java/lang/Long")
            "S" -> Pair("shortValue", "java/lang/Short")
            "Z" -> Pair("booleanValue", "java/lang/Boolean")
            else -> return
        }
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            wrappedTypeDescriptor,
            methodName,
            "()$primitiveTypeDescriptor",
            false
        )
    }
}
