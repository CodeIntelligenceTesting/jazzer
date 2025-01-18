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

import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.utils.Log
import org.objectweb.asm.Handle
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.commons.AnalyzerAdapter
import org.objectweb.asm.commons.LocalVariablesSorter
import java.util.concurrent.atomic.AtomicBoolean

internal fun makeHookMethodVisitor(
    owner: String,
    access: Int,
    name: String?,
    descriptor: String?,
    methodVisitor: MethodVisitor?,
    hooks: Iterable<Hook>,
    java6Mode: Boolean,
    random: DeterministicRandom,
    classWithHooksEnabledField: String?,
): MethodVisitor =
    HookMethodVisitor(
        owner,
        access,
        name,
        descriptor,
        methodVisitor,
        hooks,
        java6Mode,
        random,
        classWithHooksEnabledField,
    ).lvs

private class HookMethodVisitor(
    owner: String,
    access: Int,
    val name: String?,
    descriptor: String?,
    methodVisitor: MethodVisitor?,
    hooks: Iterable<Hook>,
    private val java6Mode: Boolean,
    private val random: DeterministicRandom,
    private val classWithHooksEnabledField: String?,
) : MethodVisitor(
        Instrumentor.ASM_API_VERSION,
        // AnalyzerAdapter computes stack map frames at every instruction, which is needed for the
        // conditional hook logic as it adds a conditional jump. Before Java 7, stack map frames were
        // neither included nor required in class files.
        //
        // Note: Delegating to AnalyzerAdapter rather than having AnalyzerAdapter delegate to our
        // MethodVisitor is unusual. We do this since we insert conditional jumps around method calls,
        // which requires knowing the stack map both before and after the call. If AnalyzerAdapter
        // delegated to this MethodVisitor, we would only be able to access the stack map before the
        // method call in visitMethodInsn.
        if (classWithHooksEnabledField != null && !java6Mode) {
            AnalyzerAdapter(
                owner,
                access,
                name,
                descriptor,
                methodVisitor,
            )
        } else {
            methodVisitor
        },
    ) {
    companion object {
        private val showUnsupportedHookWarning = AtomicBoolean(true)
    }

    val lvs =
        object : LocalVariablesSorter(Instrumentor.ASM_API_VERSION, access, descriptor, this) {
            override fun updateNewLocals(newLocals: Array<Any>) {
                // The local variables involved in calling hooks do not need to outlive the current
                // basic block and should thus not appear in stack map frames. By requesting the
                // LocalVariableSorter to fill their entries in stack map frames with TOP, they will
                // be treated like an unused local variable slot.
                newLocals.fill(Opcodes.TOP)
            }
        }

    private val hooks =
        hooks.groupBy { hook ->
            var hookKey = "${hook.hookType}#${hook.targetInternalClassName}#${hook.targetMethodName}"
            if (hook.targetMethodDescriptor != null) {
                hookKey += "#${hook.targetMethodDescriptor}"
            }
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
        handleMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
    }

    // Transforms a stack map specification from the form used by the JVM and AnalyzerAdapter, where
    // LONG and DOUBLE values are followed by an additional TOP entry, to the form accepted by
    // visitFrame, which doesn't expect this additional entry.
    private fun dropImplicitTop(stack: Collection<Any>?): Array<Any>? {
        if (stack == null) {
            return null
        }
        val filteredStack = mutableListOf<Any>()
        var previousElement: Any? = null
        for (element in stack) {
            if (element != Opcodes.TOP || (previousElement != Opcodes.DOUBLE && previousElement != Opcodes.LONG)) {
                filteredStack.add(element)
            }
            previousElement = element
        }
        return filteredStack.toTypedArray()
    }

    private fun storeFrame(aa: AnalyzerAdapter?): Pair<Array<Any>?, Array<Any>?>? {
        return Pair(dropImplicitTop((aa ?: return null).locals), dropImplicitTop(aa.stack))
    }

    fun handleMethodInsn(
        opcode: Int,
        owner: String,
        methodName: String,
        methodDescriptor: String,
        isInterface: Boolean,
    ) {
        val matchingHooks = findMatchingHooks(owner, methodName, methodDescriptor)

        if (matchingHooks.isEmpty()) {
            mv.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
            return
        }

        val skipHooksLabel = Label()
        val applyHooksLabel = Label()
        val useConditionalHooks = classWithHooksEnabledField != null
        var postCallFrame: Pair<Array<Any>?, Array<Any>?>? = null
        if (useConditionalHooks) {
            val preCallFrame = (mv as? AnalyzerAdapter)?.let { storeFrame(it) }
            // If hooks aren't enabled, skip the hook invocations.
            mv.visitFieldInsn(
                Opcodes.GETSTATIC,
                classWithHooksEnabledField,
                "hooksEnabled",
                "Z",
            )
            mv.visitJumpInsn(Opcodes.IFNE, applyHooksLabel)
            mv.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
            postCallFrame = (mv as? AnalyzerAdapter)?.let { storeFrame(it) }
            mv.visitJumpInsn(Opcodes.GOTO, skipHooksLabel)
            // Needs a stack map frame as both the successor of an unconditional jump and the target
            // of a jump.
            mv.visitLabel(applyHooksLabel)
            if (preCallFrame != null) {
                mv.visitFrame(
                    Opcodes.F_NEW,
                    preCallFrame.first?.size ?: 0,
                    preCallFrame.first,
                    preCallFrame.second?.size ?: 0,
                    preCallFrame.second,
                )
            }
            // All successor instructions emitted below do not have a stack map frame attached, so
            // we do not need to emit a NOP to prevent duplicated stack map frames.
        }

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

        val returnTypeDescriptor = extractReturnTypeDescriptor(methodDescriptor)
        // Create a local variable to store the return value
        val localReturnObj = lvs.newLocal(Type.getType(getWrapperTypeDescriptor(returnTypeDescriptor)))

        matchingHooks.forEachIndexed { index, hook ->
            // The hookId is used to identify a call site.
            val hookId = random.nextInt()

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
                val handleOpcode =
                    when (opcode) {
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
                            isInterface,
                        ),
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
                        false,
                    )

                    // Call the original method if this is the last BEFORE hook. If not, the original method will be
                    // called by the next AFTER hook.
                    if (index == matchingHooks.lastIndex) {
                        // Stack layout: ...
                        // Push the values for the original method call onto the stack again
                        if (opcode != Opcodes.INVOKESTATIC) {
                            mv.visitVarInsn(Opcodes.ALOAD, localOwnerObj) // push owner object
                        }
                        loadMethodArguments(paramDescriptors, localObjArr) // push all method arguments
                        // Stack layout: ... | [owner (objectref)] | arg1 (primitive/objectref) | arg2 (primitive/objectref) | ...
                        mv.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
                    }
                }

                HookType.REPLACE -> {
                    // Call the hook method
                    mv.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        hook.hookInternalClassName,
                        hook.hookMethodName,
                        hook.hookMethodDescriptor,
                        false,
                    )
                    // Stack layout: ... | [return value (primitive/objectref)]
                    // Check if we need to process the return value
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
                    // Call the original method before the first AFTER hook
                    if (index == 0 || matchingHooks[index - 1].hookType != HookType.AFTER) {
                        // Push the values for the original method call again onto the stack
                        if (opcode != Opcodes.INVOKESTATIC) {
                            mv.visitVarInsn(Opcodes.ALOAD, localOwnerObj) // push owner object
                        }
                        loadMethodArguments(paramDescriptors, localObjArr) // push all method arguments
                        // Stack layout: ... | MethodHandle (objectref) | owner (objectref) | object array (arrayref) | hookId (int)
                        //                   | [owner (objectref)] | arg1 (primitive/objectref) | arg2 (primitive/objectref) | ...
                        mv.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface)
                        if (returnTypeDescriptor == "V") {
                            // If the method didn't return anything, we push a nullref as placeholder
                            mv.visitInsn(Opcodes.ACONST_NULL) // push nullref
                        }
                        // Wrap return value if it is a primitive type
                        wrapTypeIfPrimitive(returnTypeDescriptor)
                        mv.visitVarInsn(Opcodes.ASTORE, localReturnObj) // consume objectref
                    }
                    mv.visitVarInsn(Opcodes.ALOAD, localReturnObj) // push objectref

                    // Stack layout: ... | MethodHandle (objectref) | owner (objectref) | object array (arrayref) | hookId (int)
                    //                   | return value (objectref)
                    // Store the result value in a local variable (but keep it on the stack)
                    // Call the hook method
                    mv.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        hook.hookInternalClassName,
                        hook.hookMethodName,
                        hook.hookMethodDescriptor,
                        false,
                    )
                    // Stack layout: ...
                    // Push the return value on the stack after the last AFTER hook if the original method returns a value
                    if (index == matchingHooks.size - 1 && returnTypeDescriptor != "V") {
                        // Push the return value again
                        mv.visitVarInsn(Opcodes.ALOAD, localReturnObj) // push objectref
                        // Unwrap it, if it was a primitive value
                        unwrapTypeIfPrimitive(returnTypeDescriptor)
                        // Stack layout: ... | return value (primitive/objectref)
                    }
                }
            }
        }
        if (useConditionalHooks) {
            // Needs a stack map frame as the target of a jump.
            mv.visitLabel(skipHooksLabel)
            if (postCallFrame != null) {
                mv.visitFrame(
                    Opcodes.F_NEW,
                    postCallFrame.first?.size ?: 0,
                    postCallFrame.first,
                    postCallFrame.second?.size ?: 0,
                    postCallFrame.second,
                )
            }
            // We do not control the next visitor calls, but we must not emit two frames for the
            // same instruction.
            mv.visitInsn(Opcodes.NOP)
        }
    }

    private fun isMethodInvocationOp(opcode: Int) =
        opcode in
            listOf(
                Opcodes.INVOKEVIRTUAL,
                Opcodes.INVOKEINTERFACE,
                Opcodes.INVOKESTATIC,
                Opcodes.INVOKESPECIAL,
            )

    private fun findMatchingHooks(
        owner: String,
        name: String,
        descriptor: String,
    ): List<Hook> {
        val result =
            HookType
                .values()
                .flatMap { hookType ->
                    val withoutDescriptorKey = "$hookType#$owner#$name"
                    val withDescriptorKey = "$withoutDescriptorKey#$descriptor"
                    hooks[withDescriptorKey].orEmpty() + hooks[withoutDescriptorKey].orEmpty()
                }.sortedBy { it.hookType }
        val replaceHookCount = result.count { it.hookType == HookType.REPLACE }
        check(
            replaceHookCount == 0 ||
                (replaceHookCount == 1 && result.size == 1),
        ) {
            "For a given method, You can either have a single REPLACE hook or BEFORE/AFTER hooks. Found:\n $result"
        }

        return result
            .filter { !isReplaceHookInJava6mode(it) }
            .sortedByDescending { it.toString() }
    }

    private fun isReplaceHookInJava6mode(hook: Hook): Boolean {
        if (java6Mode && hook.hookType == HookType.REPLACE) {
            if (showUnsupportedHookWarning.getAndSet(false)) {
                Log.warn(
                    """Some hooks could not be applied to class files built for Java 7 or lower.
                       Ensure that the fuzz target and its dependencies are compiled with
                       -target 8 or higher to identify as many bugs as possible.
                    """.trimMargin(),
                )
            }
            return true
        }
        return false
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
    private fun loadMethodArguments(
        paramDescriptors: List<String>,
        localObjArr: Int,
    ) {
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
    // and pushes it enclosed in its wrapper type (e.g. removes int, pushes Integer).
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
        val (methodName, wrappedTypeDescriptor) =
            when (primitiveTypeDescriptor) {
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
            false,
        )
    }
}
