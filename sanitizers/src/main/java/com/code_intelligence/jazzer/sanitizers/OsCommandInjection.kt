/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

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
        additionalClassesToHook = ["java.lang.ProcessBuilder"],
    )
    @JvmStatic
    fun processImplStartHook(method: MethodHandle?, alwaysNull: Any?, args: Array<Any?>, hookId: Int) {
        if (args.isEmpty()) { return }
        // Calling ProcessBuilder already checks if command array is empty
        @Suppress("UNCHECKED_CAST")
        (args[0] as? Array<String>)?.first().let { cmd ->
            if (cmd == COMMAND) {
                Jazzer.reportFindingFromHook(
                    FuzzerSecurityIssueCritical(
                        """OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.""",
                    ),
                )
            } else {
                Jazzer.guideTowardsEquality(cmd, COMMAND, hookId)
            }
        }
    }
}
