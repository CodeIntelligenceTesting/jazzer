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
import java.lang.invoke.MethodHandle

/**
 * Detects unsafe reflective calls that lead to attacker-controlled method calls.
 */
@Suppress("unused_parameter")
object ReflectiveCall {

    @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Class", targetMethod = "forName")
    @JvmStatic
    fun classForNameHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        val className = args[0] as? String ?: return
        Jazzer.guideTowardsEquality(className, HONEYPOT_CLASS_NAME, hookId)
    }
}
