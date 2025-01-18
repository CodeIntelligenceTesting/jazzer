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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import com.code_intelligence.jazzer.api.MethodHooks
import java.lang.Exception
import java.lang.invoke.MethodHandle
import javax.naming.NamingException
import javax.naming.directory.InvalidSearchFilterException

/**
 * Detects LDAP DN and search filter injections.
 *
 * Untrusted input has to be escaped in such a way that queries remain valid otherwise an injection
 * could be possible. This sanitizer guides the fuzzer to inject insecure characters. If an exception
 * is raised during execution the fuzzer was able to inject an invalid pattern, otherwise all input
 * was escaped correctly.
 *
 * Only the search methods are hooked, other methods are not used in injection attacks. Furthermore,
 * only string parameters are checked, [javax.naming.Name] already validates inputs according to RFC2253.
 *
 * [javax.naming.directory.InitialDirContext] creates an initial context through the context factory
 * stated in [javax.naming.Context.INITIAL_CONTEXT_FACTORY]. Other method calls are delegated to the
 * initial context factory of type [javax.naming.directory.DirContext]. This is also the case for
 * subclass [javax.naming.ldap.InitialLdapContext].
 */
@Suppress("unused_parameter", "unused")
object LdapInjection {
    // Characters to escape in DNs
    private const val NAME_CHARACTERS = "\\+<>,;\"="

    // Characters to escape in search filter queries
    private const val FILTER_CHARACTERS = "*()\\\u0000"

    @Suppress("ktlint:standard:max-line-length")
    @MethodHooks(
        // Single object lookup, possible DN injection
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.directory.DirContext",
            targetMethod = "search",
            targetMethodDescriptor = "(Ljava/lang/String;Ljavax/naming.directory/Attributes;)Ljavax/naming/NamingEnumeration;",
            additionalClassesToHook = ["javax.naming.directory.InitialDirContext"],
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.directory.DirContext",
            targetMethod = "search",
            targetMethodDescriptor = "(Ljava/lang/String;Ljavax/naming.directory/Attributes;[Ljava/lang/Sting;)Ljavax/naming/NamingEnumeration;",
            additionalClassesToHook = ["javax.naming.directory.InitialDirContext"],
        ),
        // Object search, possible DN and search filter injection
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.directory.DirContext",
            targetMethod = "search",
            targetMethodDescriptor = "(Ljava/lang/String;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;",
            additionalClassesToHook = ["javax.naming.directory.InitialDirContext"],
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.directory.DirContext",
            targetMethod = "search",
            targetMethodDescriptor = "(Ljavax/naming/Name;Ljava/lang/String;[Ljava.lang.Object;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;",
            additionalClassesToHook = ["javax.naming.directory.InitialDirContext"],
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "javax.naming.directory.DirContext",
            targetMethod = "search",
            targetMethodDescriptor = "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;",
            additionalClassesToHook = ["javax.naming.directory.InitialDirContext"],
        ),
    )
    @JvmStatic
    fun searchLdapContext(
        method: MethodHandle,
        thisObject: Any?,
        args: Array<Any>,
        hookId: Int,
    ): Any? {
        try {
            return method.invokeWithArguments(thisObject, *args).also {
                (args[0] as? String)?.let { name ->
                    Jazzer.guideTowardsEquality(name, NAME_CHARACTERS, hookId)
                }
                (args[1] as? String)?.let { filter ->
                    Jazzer.guideTowardsEquality(filter, FILTER_CHARACTERS, 31 * hookId)
                }
            }
        } catch (e: Exception) {
            when (e) {
                is InvalidSearchFilterException ->
                    Jazzer.reportFindingFromHook(
                        FuzzerSecurityIssueCritical(
                            """LDAP Injection
Search filters based on untrusted data must be escaped as specified in RFC 4515.""",
                        ),
                    )
                is NamingException ->
                    Jazzer.reportFindingFromHook(
                        FuzzerSecurityIssueCritical(
                            """LDAP Injection 
Distinguished Names based on untrusted data must be escaped as specified in RFC 2253.""",
                        ),
                    )
            }
            throw e
        }
    }
}
