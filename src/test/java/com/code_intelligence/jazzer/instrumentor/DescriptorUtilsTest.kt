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

import org.junit.Test
import kotlin.test.assertEquals

class DescriptorUtilsTest {
    @Test
    fun testClassDescriptor() {
        assertEquals("V", java.lang.Void::class.javaPrimitiveType?.descriptor)
        assertEquals("J", java.lang.Long::class.javaPrimitiveType?.descriptor)
        assertEquals("[[[Z", Array<Array<BooleanArray>>::class.java.descriptor)
        assertEquals("[Ljava/lang/String;", Array<String>::class.java.descriptor)
    }

    @Test
    fun testExtractInternalClassName() {
        assertEquals("java/lang/String", extractInternalClassName("Ljava/lang/String;"))
        assertEquals("[Ljava/lang/String;", extractInternalClassName("[Ljava/lang/String;"))
        assertEquals("B", extractInternalClassName("B"))
    }

    @Test
    fun testExtractTypeDescriptors() {
        val testCases =
            listOf(
                Triple(
                    String::class.java.getMethod("equals", Object::class.java),
                    listOf("Ljava/lang/Object;"),
                    "Z",
                ),
                Triple(
                    String::class.java.getMethod(
                        "regionMatches",
                        Boolean::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        String::class.java,
                        Int::class.javaPrimitiveType,
                        Integer::class.javaPrimitiveType,
                    ),
                    listOf("Z", "I", "Ljava/lang/String;", "I", "I"),
                    "Z",
                ),
                Triple(
                    String::class.java.getMethod(
                        "getChars",
                        Integer::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        CharArray::class.java,
                        Int::class.javaPrimitiveType,
                    ),
                    listOf("I", "I", "[C", "I"),
                    "V",
                ),
                Triple(
                    String::class.java.getMethod("subSequence", Integer::class.javaPrimitiveType, Integer::class.javaPrimitiveType),
                    listOf("I", "I"),
                    "Ljava/lang/CharSequence;",
                ),
                Triple(
                    String::class.java.getConstructor(),
                    emptyList(),
                    "V",
                ),
            )
        for ((executable, parameterDescriptors, returnTypeDescriptor) in testCases) {
            val descriptor = executable.descriptor
            assertEquals(extractParameterTypeDescriptors(descriptor), parameterDescriptors)
            assertEquals(extractReturnTypeDescriptor(descriptor), returnTypeDescriptor)
        }
    }
}
