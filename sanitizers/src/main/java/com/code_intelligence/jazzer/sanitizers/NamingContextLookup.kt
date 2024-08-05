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
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.invoke.MethodHandle
import javax.naming.CommunicationException

@Suppress("unused")
object NamingContextLookup {

    // The particular URL g.co is used here since it is:
    // - short, which makes it easier for the fuzzer to incorporate into the input;
    // - valid, which means that a `lookup` call on it could actually result in RCE;
    // - highly reputable, which makes it very unlikely that it would ever host an actual exploit.
    private const val LDAP_MARKER = "ldap://g.co/"
    private const val RMI_MARKER = "rmi://g.co/"

    @Suppress("UNUSED_PARAMETER")
    @MethodHooks(
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.Context",
            targetMethod = "lookup",
            targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/Object;",
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.Context",
            targetMethod = "lookupLink",
            targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/Object;",
        ),
    )
    @JvmStatic
    fun lookupHook(method: MethodHandle?, thisObject: Any?, args: Array<Any?>, hookId: Int): Any {
        val name = args[0] as? String ?: throw CommunicationException()
        if (name.startsWith(RMI_MARKER) || name.startsWith(LDAP_MARKER)) {
            Jazzer.reportFindingFromHook(
                FuzzerSecurityIssueCritical(
                    """Remote JNDI Lookup
JNDI lookups with attacker-controlled remote URLs can, depending on the JDK
version, lead to remote code execution or the exfiltration of information.""",
                ),
            )
        }
        Jazzer.guideTowardsEquality(name, RMI_MARKER, hookId)
        Jazzer.guideTowardsEquality(name, LDAP_MARKER, 31 * hookId)
        // Pretend that the remote endpoint could not be reached for additional protection against
        // accidental execution of remote code during fuzzing.
        throw CommunicationException()
    }
}
