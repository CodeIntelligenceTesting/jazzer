package com.code_intelligence.jazzer.sanitizers

import com.code_intelligence.jazzer.api.*
import com.code_intelligence.jazzer.api.MethodHook
import java.lang.invoke.MethodHandle
import java.net.InetSocketAddress

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
                """.trimIndent()
            )
        )
    }
}