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

@file:Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")

package com.code_intelligence.jazzer.instrumentor

import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import com.code_intelligence.jazzer.utils.descriptor
import java.lang.invoke.MethodHandle
import java.lang.reflect.Method
import java.lang.reflect.Modifier

class Hook private constructor(hookMethod: Method, annotation: MethodHook) {
    // Allowing arbitrary exterior whitespace in the target class name allows for an easy workaround
    // for mangled hooks due to shading applied to hooks.
    private val targetClassName = annotation.targetClassName.trim()
    val targetMethodName = annotation.targetMethod
    val targetMethodDescriptor = annotation.targetMethodDescriptor.takeIf { it.isNotEmpty() }
    val hookType = annotation.type

    val targetInternalClassName = targetClassName.replace('.', '/')
    private val targetReturnTypeDescriptor = targetMethodDescriptor?.let { extractReturnTypeDescriptor(it) }
    private val targetWrappedReturnTypeDescriptor = targetReturnTypeDescriptor?.let { getWrapperTypeDescriptor(it) }

    private val hookClassName: String = hookMethod.declaringClass.name
    val hookInternalClassName = hookClassName.replace('.', '/')
    val hookMethodName: String = hookMethod.name
    val hookMethodDescriptor = hookMethod.descriptor

    override fun toString(): String {
        return "$hookType $targetClassName.$targetMethodName: $hookClassName.$hookMethodName"
    }

    companion object {

        fun verifyAndGetHook(hookMethod: Method, hookData: MethodHook): Hook {
            // Verify the annotation type and extract information for debug statements.
            val potentialHook = Hook(hookMethod, hookData)

            // Verify the hook method's modifiers (public static).
            require(Modifier.isPublic(hookMethod.modifiers)) { "$potentialHook: hook method must be public" }
            require(Modifier.isStatic(hookMethod.modifiers)) { "$potentialHook: hook method must be static" }

            // Verify the hook method's parameter count.
            val numParameters = hookMethod.parameters.size
            when (hookData.type) {
                HookType.BEFORE, HookType.REPLACE -> require(numParameters == 4) { "$potentialHook: incorrect number of parameters (expected 4)" }
                HookType.AFTER -> require(numParameters == 5) { "$potentialHook: incorrect number of parameters (expected 5)" }
            }

            // Verify the hook method's parameter types.
            val parameterTypes = hookMethod.parameterTypes
            require(parameterTypes[0] == MethodHandle::class.java) { "$potentialHook: first parameter must have type MethodHandle" }
            require(parameterTypes[1] == Object::class.java || parameterTypes[1].name == potentialHook.targetClassName) { "$potentialHook: second parameter must have type Object or ${potentialHook.targetClassName}" }
            require(parameterTypes[2] == Array<Object>::class.java) { "$potentialHook: third parameter must have type Object[]" }
            require(parameterTypes[3] == Int::class.javaPrimitiveType) { "$potentialHook: fourth parameter must have type int" }

            // Verify the hook method's return type if possible.
            when (hookData.type) {
                HookType.BEFORE, HookType.AFTER -> require(hookMethod.returnType == Void.TYPE) {
                    "$potentialHook: return type must be void"
                }
                HookType.REPLACE -> if (potentialHook.targetReturnTypeDescriptor != null) {
                    val returnTypeDescriptor = hookMethod.returnType.descriptor
                    if (potentialHook.targetReturnTypeDescriptor == "V") {
                        require(returnTypeDescriptor == "V") { "$potentialHook: return type must be void to match targetMethodDescriptor" }
                    } else {
                        require(
                            returnTypeDescriptor in listOf(
                                java.lang.Object::class.java.descriptor,
                                potentialHook.targetReturnTypeDescriptor,
                                potentialHook.targetWrappedReturnTypeDescriptor
                            )
                        ) {
                            "$potentialHook: return type must have type Object or match the descriptors ${potentialHook.targetReturnTypeDescriptor} or ${potentialHook.targetWrappedReturnTypeDescriptor}"
                        }
                    }
                }
            }

            // AfterMethodHook only: Verify the type of the last parameter if known.
            if (hookData.type == HookType.AFTER && potentialHook.targetReturnTypeDescriptor != null) {
                require(
                    parameterTypes[4] == java.lang.Object::class.java ||
                        parameterTypes[4].descriptor == potentialHook.targetWrappedReturnTypeDescriptor
                ) {
                    "$potentialHook: fifth parameter must have type Object or match the descriptor ${potentialHook.targetWrappedReturnTypeDescriptor}"
                }
            }

            return potentialHook
        }
    }
}

fun loadHooks(hookClass: Class<*>): List<Hook> {
    val hooks = mutableListOf<Hook>()
    for (method in hookClass.methods) {
        method.getAnnotation(MethodHook::class.java)?.let { hooks.add(Hook.verifyAndGetHook(method, it)) }
        method.getAnnotation(MethodHooks::class.java)?.let {
            it.value.forEach { hookAnnotation -> hooks.add(Hook.verifyAndGetHook(method, hookAnnotation)) }
        }
    }
    return hooks
}
