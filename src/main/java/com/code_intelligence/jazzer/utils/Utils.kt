/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */
@file:JvmName("Utils")

package com.code_intelligence.jazzer.utils

import java.lang.reflect.Executable

val Class<*>.readableDescriptor: String
    get() = when {
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
    get() = parameterTypes.joinToString(separator = ",", prefix = "(", postfix = ")") { parameterType ->
        parameterType.readableDescriptor
    }
