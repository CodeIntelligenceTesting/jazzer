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

import org.objectweb.asm.Type
import java.lang.reflect.Constructor
import java.lang.reflect.Executable
import java.lang.reflect.Method

val Class<*>.descriptor: String
    get() = Type.getDescriptor(this)

val Executable.descriptor: String
    get() =
        if (this is Method) {
            Type.getMethodDescriptor(this)
        } else {
            Type.getConstructorDescriptor(this as Constructor<*>?)
        }

internal fun isPrimitiveType(typeDescriptor: String): Boolean = typeDescriptor in arrayOf("B", "C", "D", "F", "I", "J", "S", "V", "Z")

private fun isPrimitiveType(typeDescriptor: Char) = isPrimitiveType(typeDescriptor.toString())

internal fun getWrapperTypeDescriptor(typeDescriptor: String): String =
    when (typeDescriptor) {
        "B" -> "Ljava/lang/Byte;"
        "C" -> "Ljava/lang/Character;"
        "D" -> "Ljava/lang/Double;"
        "F" -> "Ljava/lang/Float;"
        "I" -> "Ljava/lang/Integer;"
        "J" -> "Ljava/lang/Long;"
        "S" -> "Ljava/lang/Short;"
        "V" -> "Ljava/lang/Void;"
        "Z" -> "Ljava/lang/Boolean;"
        else -> typeDescriptor
    }

// Removes the 'L' and ';' prefix/suffix from signatures to get the full class name.
// Note that array signatures '[Ljava/lang/String;' already have the correct form.
internal fun extractInternalClassName(typeDescriptor: String): String =
    if (typeDescriptor.startsWith("L") && typeDescriptor.endsWith(";")) {
        typeDescriptor.substring(1, typeDescriptor.length - 1)
    } else {
        typeDescriptor
    }

internal fun extractParameterTypeDescriptors(methodDescriptor: String): List<String> {
    require(methodDescriptor.startsWith('(')) { "Method descriptor must start with '('" }
    val endOfParameterPart = methodDescriptor.indexOf(')') - 1
    require(endOfParameterPart >= 0) { "Method descriptor must contain ')'" }
    var remainingDescriptorList = methodDescriptor.substring(1..endOfParameterPart)
    val parameterDescriptors = mutableListOf<String>()
    while (remainingDescriptorList.isNotEmpty()) {
        val nextDescriptor = extractNextTypeDescriptor(remainingDescriptorList)
        parameterDescriptors.add(nextDescriptor)
        remainingDescriptorList = remainingDescriptorList.removePrefix(nextDescriptor)
    }
    return parameterDescriptors
}

internal fun extractReturnTypeDescriptor(methodDescriptor: String): String {
    require(methodDescriptor.startsWith('(')) { "Method descriptor must start with '('" }
    val endBracketPos = methodDescriptor.indexOf(')')
    require(endBracketPos >= 0) { "Method descriptor must contain ')'" }
    val startOfReturnValue = endBracketPos + 1
    return extractNextTypeDescriptor(methodDescriptor.substring(startOfReturnValue))
}

private fun extractNextTypeDescriptor(input: String): String {
    require(input.isNotEmpty()) { "Type descriptor must not be empty" }
    // Skip over arbitrarily many '[' to support multi-dimensional arrays.
    val firstNonArrayPrefixCharPos = input.indexOfFirst { it != '[' }
    require(firstNonArrayPrefixCharPos >= 0) { "Array descriptor must contain type" }
    val firstTypeChar = input[firstNonArrayPrefixCharPos]
    return when {
        // Primitive type
        isPrimitiveType(firstTypeChar) -> {
            input.substring(0..firstNonArrayPrefixCharPos)
        }
        // Object type
        firstTypeChar == 'L' -> {
            val endOfClassNamePos = input.indexOf(';')
            require(endOfClassNamePos > 0) { "Class type indicated by L must end with ;" }
            input.substring(0..endOfClassNamePos)
        }
        // Invalid type
        else -> {
            throw IllegalArgumentException("Invalid type: $firstTypeChar")
        }
    }
}
