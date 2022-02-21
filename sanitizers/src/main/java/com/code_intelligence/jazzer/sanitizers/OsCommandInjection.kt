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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import java.lang.invoke.MethodHandle

/**
 * Detects unsafe execution of OS commands using [ProcessBuilder].
 * Executing OS commands based on attacker-controlled data could lead to arbitrary could execution.
 *
 * All public methods providing the command to execute end up in [java.lang.ProcessImpl.start],
 * so calls to this method are hooked.
 * Only the first entry of the given command array is analyzed. It states the executable and must
 * not include attacker provided data.
 */
@Suppress("unused_parameter", "unused")
object OsCommandInjection {

    // Short and probably non-existing command name
    private const val COMMAND = "jazze"

    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.lang.ProcessImpl",
        targetMethod = "start",
        additionalClassesToHook = ["java.lang.ProcessBuilder"]
    )
    @JvmStatic
    fun processImplStartHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        // Calling ProcessBuilder already checks if command array is empty
        @Suppress("UNCHECKED_CAST")
        (args[0] as? Array<String>)?.first().let { cmd ->
            if (cmd == COMMAND) {
                Jazzer.reportFindingFromHook(
                    FuzzerSecurityIssueCritical(
                        """OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution."""
                    )
                )
            } else {
                Jazzer.guideTowardsEquality(cmd, COMMAND, hookId)
            }
        }
    }
}
