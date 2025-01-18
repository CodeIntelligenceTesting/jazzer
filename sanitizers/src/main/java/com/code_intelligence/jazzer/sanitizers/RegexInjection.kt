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

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.invoke.MethodHandle
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

// message introduced in JDK14 and ported back to previous versions
private const val STACK_OVERFLOW_ERROR_MESSAGE = "Stack overflow during pattern compilation"

@Suppress("unused_parameter", "unused")
object RegexInjection {
    /**
     * Part of an OOM "exploit" for [java.util.regex.Pattern.compile] with the
     * [java.util.regex.Pattern.CANON_EQ] flag, formed by three consecutive combining marks, in this
     * case grave accents: ◌̀.
     * See [compileWithFlagsHook] for details.
     */
    private const val CANON_EQ_ALMOST_EXPLOIT = "\u0300\u0300\u0300"

    /**
     * When injected into a regex pattern, helps the fuzzer break out of quotes and character
     * classes in order to cause a [PatternSyntaxException].
     */
    private const val FORCE_PATTERN_SYNTAX_EXCEPTION_PATTERN = "\\E]\\E]]]]]]"

    @MethodHook(
        type = HookType.REPLACE,
        targetClassName = "java.util.regex.Pattern",
        targetMethod = "compile",
        targetMethodDescriptor = "(Ljava/lang/String;I)Ljava/util/regex/Pattern;",
    )
    @JvmStatic
    fun compileWithFlagsHook(
        method: MethodHandle,
        alwaysNull: Any?,
        args: Array<Any?>,
        hookId: Int,
    ): Any? {
        val pattern = args[0] as String?
        val hasCanonEqFlag = ((args[1] as Int) and Pattern.CANON_EQ) != 0
        return hookInternal(method, pattern, hasCanonEqFlag, hookId, *args)
    }

    @MethodHooks(
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.util.regex.Pattern",
            targetMethod = "compile",
            targetMethodDescriptor = "(Ljava/lang/String;)Ljava/util/regex/Pattern;",
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.util.regex.Pattern",
            targetMethod = "matches",
            targetMethodDescriptor = "(Ljava/lang/String;Ljava/lang/CharSequence;)Z",
        ),
    )
    @JvmStatic
    fun patternHook(
        method: MethodHandle,
        alwaysNull: Any?,
        args: Array<Any?>,
        hookId: Int,
    ): Any? = hookInternal(method, args[0] as String?, false, hookId, *args)

    @MethodHooks(
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.lang.String",
            targetMethod = "matches",
            targetMethodDescriptor = "(Ljava/lang/String;)Z",
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.lang.String",
            targetMethod = "replaceAll",
            targetMethodDescriptor = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.lang.String",
            targetMethod = "replaceFirst",
            targetMethodDescriptor = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.lang.String",
            targetMethod = "split",
            targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/String;",
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.lang.String",
            targetMethod = "split",
            targetMethodDescriptor = "(Ljava/lang/String;I)Ljava/lang/String;",
        ),
    )
    @JvmStatic
    fun stringHook(
        method: MethodHandle,
        thisObject: Any?,
        args: Array<Any?>,
        hookId: Int,
    ): Any? = hookInternal(method, args[0] as String?, false, hookId, thisObject, *args)

    private fun hookInternal(
        method: MethodHandle,
        pattern: String?,
        hasCanonEqFlag: Boolean,
        hookId: Int,
        vararg args: Any?,
    ): Any? {
        if (hasCanonEqFlag && pattern != null) {
            // With CANON_EQ enabled, Pattern.compile allocates an array with a size that is
            // (super-)exponential in the number of consecutive Unicode combining marks. We use a mild case
            // of this as a magic string based on which we trigger a finding.
            // Note: The fuzzer might trigger an OutOfMemoryError or NegativeArraySizeException (if the size
            // of the array overflows an int) by chance before it correctly emits this "exploit". In that
            // case, we report the original exception instead.
            if (pattern.contains(CANON_EQ_ALMOST_EXPLOIT)) {
                Jazzer.reportFindingFromHook(
                    FuzzerSecurityIssueLow(
                        """Regular Expression Injection with CANON_EQ
When java.util.regex.Pattern.compile is used with the Pattern.CANON_EQ flag,
every injection into the regular expression pattern can cause arbitrarily large
memory allocations, even when wrapped with Pattern.quote(...).""",
                    ),
                )
            } else {
                Jazzer.guideTowardsContainment(pattern, CANON_EQ_ALMOST_EXPLOIT, hookId)
            }
        }
        try {
            return method.invokeWithArguments(*args).also {
                // Only submit a fuzzer hint if no exception has been thrown.
                if (!hasCanonEqFlag && pattern != null) {
                    Jazzer.guideTowardsContainment(pattern, FORCE_PATTERN_SYNTAX_EXCEPTION_PATTERN, hookId)
                }
            }
        } catch (e: Exception) {
            if (e is PatternSyntaxException && !(e.message ?: "").startsWith(STACK_OVERFLOW_ERROR_MESSAGE)) {
                Jazzer.reportFindingFromHook(
                    FuzzerSecurityIssueLow(
                        """Regular Expression Injection
Regular expression patterns that contain unescaped untrusted input can consume
arbitrary amounts of CPU time. To properly escape the input, wrap it with
Pattern.quote(...).""",
                        e,
                    ),
                )
            }
            throw e
        }
    }
}
