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
@file:JvmName("Utils")

package com.code_intelligence.jazzer.utils

import java.lang.reflect.Executable
import java.lang.reflect.Method
import java.nio.ByteBuffer
import java.security.MessageDigest

val Class<*>.descriptor: String
    get() = when {
        isPrimitive -> {
            when (this) {
                Boolean::class.javaPrimitiveType -> "Z"
                Byte::class.javaPrimitiveType -> "B"
                Char::class.javaPrimitiveType -> "C"
                Short::class.javaPrimitiveType -> "S"
                Int::class.javaPrimitiveType -> "I"
                Long::class.javaPrimitiveType -> "J"
                Float::class.javaPrimitiveType -> "F"
                Double::class.javaPrimitiveType -> "D"
                java.lang.Void::class.javaPrimitiveType -> "V"
                else -> throw IllegalStateException("Unknown primitive type: $name")
            }
        }
        isArray -> "[${componentType.descriptor}"
        java.lang.Object::class.java.isAssignableFrom(this) -> "L${name.replace('.', '/')};"
        else -> throw IllegalArgumentException("Unknown class type: $name")
    }

val Executable.descriptor: String
    get() = parameterTypes.joinToString(separator = "", prefix = "(", postfix = ")") { parameterType ->
        parameterType.descriptor
    } + if (this is Method) returnType.descriptor else "V"

fun simpleFastHash(vararg strings: String): Int {
    var hash = 0
    for (string in strings) {
        for (c in string) {
            hash = hash * 11 + c.toInt()
        }
    }
    return hash
}

private fun hash(throwable: Throwable): ByteArray = MessageDigest.getInstance("SHA-256").run {
    // It suffices to hash the stack trace of the deepest cause as the higher-level causes only
    // contain part of the stack trace (plus possibly a different exception type).
    var rootCause = throwable
    while (true) {
        rootCause = rootCause.cause ?: break
    }
    update(rootCause.javaClass.name.toByteArray())
    for (element in rootCause.stackTrace) {
        update(element.toString().toByteArray())
    }
    if (throwable.suppressed.isNotEmpty()) {
        update("suppressed".toByteArray())
        for (suppressed in throwable.suppressed) {
            update(hash(suppressed))
        }
    }
    digest()
}

/**
 * Computes a hash of the stack trace of [throwable] without messages.
 *
 * The hash can be used to deduplicate stack traces obtained on crashes. By not including the
 * messages, this hash should not depend on the precise crashing input.
 */
fun computeDedupToken(throwable: Throwable): Long {
    return ByteBuffer.wrap(hash(throwable)).long
}
