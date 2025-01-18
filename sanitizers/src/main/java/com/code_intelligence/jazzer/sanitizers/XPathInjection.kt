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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.invoke.MethodHandle
import javax.xml.xpath.XPathExpressionException

/**
 * Detects XPath injections.
 *
 * Untrusted input has to be escaped in such a way that queries remain valid, otherwise an injection
 * could be possible. This sanitizer guides the fuzzer to inject insecure characters. If an exception
 * is raised during execution the fuzzer was able to inject an invalid pattern, otherwise all input
 * was escaped correctly.
 * Checking if the innermost cause of XPathExpressionException is a TransformerException should
 * indicate injection instead of a false positive.
 */
@Suppress("unused_parameter", "unused")
object XPathInjection {
    // Characters that should be escaped in user input.
    // https://owasp.org/www-community/attacks/XPATH_Injection
    private const val CHARACTERS_TO_ESCAPE = "'\""

    private val XPATH_SYNTAX_ERROR_EXCEPTIONS = "javax.xml.transform.TransformerException"

    @MethodHooks(
        MethodHook(type = HookType.REPLACE, targetClassName = "javax.xml.xpath.XPath", targetMethod = "compile"),
        MethodHook(type = HookType.REPLACE, targetClassName = "javax.xml.xpath.XPath", targetMethod = "evaluate"),
        MethodHook(type = HookType.REPLACE, targetClassName = "javax.xml.xpath.XPath", targetMethod = "evaluateExpression"),
    )
    @JvmStatic
    fun checkXpathExecute(
        method: MethodHandle,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ): Any {
        if (arguments.isNotEmpty() && arguments[0] is String) {
            val query = arguments[0] as String
            Jazzer.guideTowardsContainment(query, CHARACTERS_TO_ESCAPE, hookId)
        }
        return try {
            method.invokeWithArguments(thisObject, *arguments)
        } catch (exception: XPathExpressionException) {
            // find innermost cause
            var innerCause = exception.cause
            while (innerCause?.cause != null && innerCause.cause != innerCause) {
                innerCause = innerCause.cause
            }

            if (innerCause != null && XPATH_SYNTAX_ERROR_EXCEPTIONS.equals(innerCause.javaClass.name)) {
                Jazzer.reportFindingFromHook(
                    FuzzerSecurityIssueHigh(
                        """
                        XPath Injection
                        Injected query: ${arguments[0]}
                        """.trimIndent(),
                        exception,
                    ),
                )
            }
            throw exception
        }
    }
}
