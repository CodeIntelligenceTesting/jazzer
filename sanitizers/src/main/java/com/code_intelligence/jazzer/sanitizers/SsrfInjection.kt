/*
 * Copyright 2022 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.api.*
import com.code_intelligence.jazzer.api.MethodHook
import java.lang.invoke.MethodHandle

@Suppress("unused_parameter", "unused")
object SsrfInjection {

    @MethodHooks(
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.net.SocketImpl",
            targetMethod = "connect",
            targetMethodDescriptor = "(Ljava/lang/String;I)V",
            additionalClassesToHook = [
                "sun.net.NetworkClient",
                "java.net.Socket",
                "java.net.SocksSocketImpl",
                "java.net.NetworkInterface",
            ],
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.net.SocketImpl",
            targetMethod = "connect",
            targetMethodDescriptor = "(Ljava/net/InetAddress;I)V",
            additionalClassesToHook = [
                "sun.net.NetworkClient",
                "java.net.Socket",
                "java.net.SocksSocketImpl",
                "java.net.NetworkInterface",
            ],
        ),
        MethodHook(
            type = HookType.REPLACE,
            targetClassName = "java.net.SocketImpl",
            targetMethod = "connect",
            targetMethodDescriptor = "(Ljava/net/SocketAddress;I)V",
            additionalClassesToHook = [
                "sun.net.NetworkClient",
                "java.net.Socket",
                "java.net.SocksSocketImpl",
                "java.net.NetworkInterface",
            ],
        ),
    )
    @JvmStatic
    fun checkSsrf(method: MethodHandle, thisObject: Any?, arguments: Array<Any>, hookId: Int) {
        // Any connection attempt is considered a SSRF
        Jazzer.reportFindingFromHook(
            FuzzerSecurityIssueHigh(
                """
                SSRF Injection
                Injected query "${arguments[0]}"
                """.trimIndent(),
            ),
        )
    }
}
