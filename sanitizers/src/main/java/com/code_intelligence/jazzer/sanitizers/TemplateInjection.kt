/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import java.io.Reader
import java.lang.invoke.MethodHandle

/**
 * Guides FreeMarker templates towards patterns that can trigger OS command injections.
 *
 * This does not report findings directly; it steers inputs towards OS command injections,
 * which are detected by another bug detector.
 */
@Suppress("unused_parameter", "unused")
object TemplateInjection {
    private const val FREEMARKER_INJECTION_ATTACK: String = "\${\"freemarker.template.utility.Execute\"?new()(\"jazze\")}"

    init {
        require(FREEMARKER_INJECTION_ATTACK.length <= 64) {
            "FreeMarker injection must fit in a table of recent compares entry (64 bytes)"
        }
    }

    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "freemarker.template.Template",
        targetMethod = "<init>",
        additionalClassesToHook = ["freemarker.template.Template"],
    )
    @JvmStatic
    fun hookFreemarker(
        method: MethodHandle?,
        thisObject: Any?,
        arguments: Array<Any>,
        hookId: Int,
    ) {
        (1..2)
            .mapNotNull { idx -> (arguments.getOrNull(idx) as? Reader) }
            .forEach { reader ->
                Jazzer.guideTowardsContainment(
                    peekMarkableReader(reader, FREEMARKER_INJECTION_ATTACK.length),
                    FREEMARKER_INJECTION_ATTACK,
                    hookId,
                )
            }
    }
}
