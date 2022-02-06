
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
     * Try to call the default constructor of the honeypot class.
     */
    private const val EXPRESSION_LANGUAGE_ATTACK =
        "\${\"\".getClass().forName(\"$HONEYPOT_CLASS_NAME\").newInstance()}"

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
    )
    @JvmStatic
    fun hookElExpressionFactory(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int
    ) {
        val expression = arguments[1] as? String ?: return
        Jazzer.guideTowardsContainment(expression, EXPRESSION_LANGUAGE_ATTACK, hookId)
    }

    // With default configurations the argument to
    // ConstraintValidatorContext.buildConstraintViolationWithTemplate() will be evaluated by an
    // Expression Language interpreter which allows arbitrary code execution if the attacker has
    // control of the method argument.
    //
    // References: CVE-2018-16621
    // https://securitylab.github.com/research/bean-validation-RCE/
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "javax.validation.ConstraintValidatorContext",
        targetMethod = "buildConstraintViolationWithTemplate"
    )
    @JvmStatic
    fun hookBuildConstraintViolationWithTemplate(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int
    ) {
        val message = arguments[0] as String
        Jazzer.guideTowardsContainment(message, EXPRESSION_LANGUAGE_ATTACK, hookId)
    }
}
