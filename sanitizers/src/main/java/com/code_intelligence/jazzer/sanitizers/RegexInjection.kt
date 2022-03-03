// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import java.lang.invoke.MethodHandle
import java.util.regex.Pattern

@Suppress("unused_parameter", "unused")
object RegexInjection {
    /**
     * Part of an OOM "exploit" for [java.util.regex.Pattern.compile] with the
     * [java.util.regex.Pattern.CANON_EQ] flag, formed by three consecutive combining marks, in this
     * case grave accents: ◌̀.
     * See [patternCompileWithFlagsHook] for details.
     */
    private const val CANON_EQ_ALMOST_EXPLOIT = "\u0300\u0300\u0300"

    // With CANON_EQ enabled, Pattern.compile allocates an array with a size that is
    // (super-)exponential in the number of consecutive Unicode combining marks. We use a mild case
    // of this as a magic string based on which we trigger a finding.
    // Note: The fuzzer might trigger an OutOfMemoryError or NegativeArraySizeException (if the size
    // of the array overflows an int) by chance before it correctly emits this "exploit". In that
    // case, we report the original exception instead.
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.util.regex.Pattern",
        targetMethod = "compile",
        targetMethodDescriptor = "(Ljava/lang/String;I)Ljava/util/regex/Pattern;"
    )
    @JvmStatic
    fun patternCompileWithFlagsHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val pattern = args[0] as? String ?: return
        val flags = args[1] as? Int ?: return
        if (flags and Pattern.CANON_EQ == 0) return
        if (pattern.contains(CANON_EQ_ALMOST_EXPLOIT)) {
            Jazzer.reportFindingFromHook(
                FuzzerSecurityIssueLow(
                    """Regular Expression Injection with CANON_EQ
When java.util.regex.Pattern.compile is used with the Pattern.CANON_EQ flag,
every injection into the regular expression pattern can cause arbitrarily large
memory allocations, even when wrapped with Pattern.quote(...)."""
                )
            )
        } else {
            Jazzer.guideTowardsContainment(pattern, CANON_EQ_ALMOST_EXPLOIT, hookId)
        }
    }
}
