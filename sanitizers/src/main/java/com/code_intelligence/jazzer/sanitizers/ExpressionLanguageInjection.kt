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

import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.invoke.MethodHandle

/**
 * Detects injectable inputs to an expression language interpreter which may lead to remote code execution.
 */
@Suppress("unused_parameter", "unused")
object ExpressionLanguageInjection {
    /**
     * Try to call the el() method of the honeypot class.
     */
    private const val EXPRESSION_LANGUAGE_ATTACK =
        "\${Byte.class.forName(\"$HONEYPOT_CLASS_NAME\").getMethod(\"el\").invoke(null)}"
    private const val SPRING_EXPRESSION_LANGUAGE_ATTACK = "T($HONEYPOT_CLASS_NAME).el()"
    private const val ELPROCESSOR_JEXL_LANGUAGE_ATTACK =
        "\"\".getClass().forName(\"$HONEYPOT_CLASS_NAME\").getMethod(\"el\").invoke(null)"
    private const val MVEL_ATTACK = "Runtime.getRuntime().exec(\"jazze\")"

    init {
        require(EXPRESSION_LANGUAGE_ATTACK.length <= 64) {
            "Expression language exploit must fit in a table of recent compares entry (64 bytes)"
        }
        require(SPRING_EXPRESSION_LANGUAGE_ATTACK.length <= 64) {
            "Expression language exploit must fit in a table of recent compares entry (64 bytes)"
        }
        require(ELPROCESSOR_JEXL_LANGUAGE_ATTACK.length <= 64) {
            "Expression language exploit must fit in a table of recent compares entry (64 bytes)"
        }
        require(MVEL_ATTACK.length <= 64) {
            "MVEL exploit must fit in a table of recent compares entry (64 bytes)"
        }
    }

    @MethodHooks(
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "javax.el.ExpressionFactory",
            targetMethod = "createValueExpression",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "javax.el.ExpressionFactory",
            targetMethod = "createMethodExpression",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "jakarta.el.ExpressionFactory",
            targetMethod = "createValueExpression",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "jakarta.el.ExpressionFactory",
            targetMethod = "createMethodExpression",
        ),
    )
    @JvmStatic
    fun hookElExpressionFactory(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        // The overloads taking a second string argument have either three or four arguments
        if (arguments.size < 3) {
            return
        }
        val expression = arguments[1] as? String ?: return
        Jazzer.guideTowardsContainment(expression, EXPRESSION_LANGUAGE_ATTACK, hookId)
    }

    @MethodHooks(
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "javax.el.ELProcessor",
            targetMethod = "eval",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "jakarta.el.ELProcessor",
            targetMethod = "eval",
        ),
    )
    @JvmStatic
    fun hookElProcessor(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.size != 1) {
            return
        }
        val message = arguments[0] as String
        Jazzer.guideTowardsContainment(message, ELPROCESSOR_JEXL_LANGUAGE_ATTACK, hookId)
    }

    // With default configurations the argument to
    // ConstraintValidatorContext.buildConstraintViolationWithTemplate() will be evaluated by an
    // Expression Language interpreter which allows arbitrary code execution if the attacker has
    // control of the method argument.
    //
    // References: CVE-2018-16621
    // https://securitylab.github.com/research/bean-validation-RCE/
    @MethodHooks(
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "javax.validation.ConstraintValidatorContext",
            targetMethod = "buildConstraintViolationWithTemplate",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "jakarta.validation.ConstraintValidatorContext",
            targetMethod = "buildConstraintViolationWithTemplate",
        ),
    )
    @JvmStatic
    fun hookBuildConstraintViolationWithTemplate(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.size != 1) {
            return
        }
        val message = arguments[0] as String
        Jazzer.guideTowardsContainment(message, EXPRESSION_LANGUAGE_ATTACK, hookId)
    }

    /**
     * Guides Spring Expression Language (SpEL) parsing towards payloads that execute RCE, enabling discovery of
     * CVE-2022-22963-like bugs where SpEL evaluation is unexpectedly attacker-controlled.
     */
    @MethodHooks(
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "org.springframework.expression.spel.standard.SpelExpressionParser",
            targetMethod = "parseRaw",
        ),
        MethodHook(
            type = HookType.BEFORE,
            targetClassName = "org.springframework.expression.common.TemplateAwareExpressionParser",
            targetMethod = "parseExpression",
        ),
    )
    @JvmStatic
    fun hookSpelParseExpression(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isEmpty()) return
        val expr = arguments[0] as? String ?: return
        Jazzer.guideTowardsContainment(expr, SPRING_EXPRESSION_LANGUAGE_ATTACK, hookId)
    }

    /**
     * Guides JEXL expression parsing towards payloads that execute RCE. Note that `parse` is
     * triggered by vulnerable public methods.
     */
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.apache.commons.jexl2.JexlEngine",
        targetMethod = "parse",
        additionalClassesToHook = ["org.apache.commons.jexl2.JexlEngine"],
    )
    @JvmStatic
    fun hookJexlParse(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isEmpty()) return
        val expr = arguments[0] as? CharSequence ?: return
        Jazzer.guideTowardsContainment(expr.toString(), ELPROCESSOR_JEXL_LANGUAGE_ATTACK, hookId)
    }

    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.mvel2.MVEL",
        targetMethod = "eval",
    )
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.mvel2.MVEL",
        targetMethod = "evalToString",
    )
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.mvel2.MVEL",
        targetMethod = "evalToBoolean",
    )
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.mvel2.MVEL",
        targetMethod = "compileExpression",
    )
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.mvel2.MVEL",
        targetMethod = "compileGetExpression",
    )
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "org.mvel2.MVEL",
        targetMethod = "compileSetExpression",
    )
    @JvmStatic
    fun mvelEval(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        if (arguments.isEmpty()) return
        val message =
            when (val arg0 = arguments[0]) {
                is String -> arg0
                is CharArray -> String(arg0)
                else -> throw IllegalArgumentException("Unexpected type for arguments[0] in ExpressionLanguageInjection hook")
            }
        Jazzer.guideTowardsContainment(message, MVEL_ATTACK, hookId)
    }
}
