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

@file:Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")

package com.code_intelligence.jazzer.instrumentor

import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.MethodHook
import java.lang.invoke.MethodHandle
import java.lang.reflect.Method
import java.lang.reflect.Modifier

class Hook private constructor(
    private val targetClassName: String,
    val hookType: HookType,
    val targetMethodName: String,
    val targetMethodDescriptor: String?,
    val additionalClassesToHook: List<String>,
    val targetInternalClassName: String,
    private val targetReturnTypeDescriptor: String?,
    private val targetWrappedReturnTypeDescriptor: String?,
    private val hookClassName: String,
    val hookInternalClassName: String,
    val hookMethodName: String,
    val hookMethodDescriptor: String,
) {
    override fun toString(): String =
        "$hookType $targetClassName.$targetMethodName: $hookClassName.$hookMethodName $additionalClassesToHook"

    companion object {
        fun createAndVerifyHook(
            hookMethod: Method,
            hookData: MethodHook,
            className: String,
        ): Hook =
            createHook(hookMethod, hookData, className).also {
                verify(hookMethod, it)
            }

        private fun createHook(
            hookMethod: Method,
            annotation: MethodHook,
            targetClassName: String,
        ): Hook {
            val targetReturnTypeDescriptor =
                annotation.targetMethodDescriptor
                    .takeIf { it.isNotBlank() }
                    ?.let { extractReturnTypeDescriptor(it) }
            val hookClassName: String = hookMethod.declaringClass.name
            return Hook(
                targetClassName = targetClassName,
                hookType = annotation.type,
                targetMethodName = annotation.targetMethod,
                targetMethodDescriptor = annotation.targetMethodDescriptor.takeIf { it.isNotBlank() },
                additionalClassesToHook = annotation.additionalClassesToHook.asList(),
                targetInternalClassName = targetClassName.replace('.', '/'),
                targetReturnTypeDescriptor = targetReturnTypeDescriptor,
                targetWrappedReturnTypeDescriptor = targetReturnTypeDescriptor?.let { getWrapperTypeDescriptor(it) },
                hookClassName = hookClassName,
                hookInternalClassName = hookClassName.replace('.', '/'),
                hookMethodName = hookMethod.name,
                hookMethodDescriptor = hookMethod.descriptor,
            )
        }

        private fun verify(
            hookMethod: Method,
            potentialHook: Hook,
        ) {
            // Verify the hook method's modifiers (public static).
            require(Modifier.isPublic(hookMethod.modifiers)) { "$potentialHook: hook method must be public" }
            require(Modifier.isStatic(hookMethod.modifiers)) { "$potentialHook: hook method must be static" }

            // Verify the hook method's parameter count.
            val numParameters = hookMethod.parameters.size
            when (potentialHook.hookType) {
                HookType.BEFORE, HookType.REPLACE ->
                    require(
                        numParameters == 4,
                    ) { "$potentialHook: incorrect number of parameters (expected 4)" }
                HookType.AFTER -> require(numParameters == 5) { "$potentialHook: incorrect number of parameters (expected 5)" }
            }

            // Verify the hook method's parameter types.
            val parameterTypes = hookMethod.parameterTypes
            require(parameterTypes[0] == MethodHandle::class.java) { "$potentialHook: first parameter must have type MethodHandle" }
            require(parameterTypes[1] == Object::class.java || parameterTypes[1].name == potentialHook.targetClassName) {
                "$potentialHook: second parameter must have type Object or ${potentialHook.targetClassName}"
            }
            require(parameterTypes[2] == Array<Object>::class.java) { "$potentialHook: third parameter must have type Object[]" }
            require(parameterTypes[3] == Int::class.javaPrimitiveType) { "$potentialHook: fourth parameter must have type int" }

            // Verify the hook method's return type if possible.
            when (potentialHook.hookType) {
                HookType.BEFORE, HookType.AFTER ->
                    require(hookMethod.returnType == Void.TYPE) {
                        "$potentialHook: return type must be void"
                    }
                HookType.REPLACE ->
                    if (potentialHook.targetReturnTypeDescriptor != null) {
                        if (potentialHook.targetMethodName == "<init>") {
                            require(hookMethod.returnType.name == potentialHook.targetClassName) {
                                "$potentialHook: return type must be ${potentialHook.targetClassName} to match target constructor"
                            }
                        } else if (potentialHook.targetReturnTypeDescriptor == "V") {
                            require(hookMethod.returnType.descriptor == "V") { "$potentialHook: return type must be void" }
                        } else {
                            require(
                                hookMethod.returnType.descriptor in
                                    listOf(
                                        java.lang.Object::class.java.descriptor,
                                        potentialHook.targetReturnTypeDescriptor,
                                        potentialHook.targetWrappedReturnTypeDescriptor,
                                    ),
                            ) {
                                "$potentialHook: return type must have type Object or match the descriptors ${potentialHook.targetReturnTypeDescriptor} or ${potentialHook.targetWrappedReturnTypeDescriptor}"
                            }
                        }
                    }
            }

            // AfterMethodHook only: Verify the type of the last parameter if known. Even if not
            // known, it must not be a primitive value.
            if (potentialHook.hookType == HookType.AFTER) {
                if (potentialHook.targetReturnTypeDescriptor != null) {
                    require(
                        parameterTypes[4] == java.lang.Object::class.java ||
                            parameterTypes[4].descriptor == potentialHook.targetWrappedReturnTypeDescriptor,
                    ) {
                        "$potentialHook: fifth parameter must have type Object or match the descriptor ${potentialHook.targetWrappedReturnTypeDescriptor}"
                    }
                } else {
                    require(!parameterTypes[4].isPrimitive) {
                        "$potentialHook: fifth parameter must not be a primitive type, use a boxed type instead"
                    }
                }
            }
        }
    }
}
