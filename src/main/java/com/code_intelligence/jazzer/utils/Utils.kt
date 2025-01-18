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
@file:JvmName("Utils")

package com.code_intelligence.jazzer.utils

import java.lang.reflect.Executable

val Class<*>.readableDescriptor: String
    get() =
        when {
            isPrimitive -> {
                when (this) {
                    Boolean::class.javaPrimitiveType -> "boolean"
                    Byte::class.javaPrimitiveType -> "byte"
                    Char::class.javaPrimitiveType -> "char"
                    Short::class.javaPrimitiveType -> "short"
                    Int::class.javaPrimitiveType -> "int"
                    Long::class.javaPrimitiveType -> "long"
                    Float::class.javaPrimitiveType -> "float"
                    Double::class.javaPrimitiveType -> "double"
                    java.lang.Void::class.javaPrimitiveType -> "void"
                    else -> throw IllegalStateException("Unknown primitive type: $name")
                }
            }
            isArray -> "${componentType.readableDescriptor}[]"
            java.lang.Object::class.java.isAssignableFrom(this) -> name
            else -> throw IllegalArgumentException("Unknown class type: $name")
        }

// This does not include the return type as the parameter descriptors already uniquely identify the executable.
val Executable.readableDescriptor: String
    get() =
        parameterTypes.joinToString(separator = ",", prefix = "(", postfix = ")") { parameterType ->
            parameterType.readableDescriptor
        }
