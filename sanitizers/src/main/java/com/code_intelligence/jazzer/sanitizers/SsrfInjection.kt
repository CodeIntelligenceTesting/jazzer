/*
 * Copyright 2023 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh
import com.code_intelligence.jazzer.api.HookType
import com.code_intelligence.jazzer.api.Jazzer
import com.code_intelligence.jazzer.api.MethodHook
import java.lang.invoke.MethodHandle
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MalformedURLException
import java.net.URL

/**
 * Detects Server Side Request Forgery vulnerabilities.
 *
 * Requests to destinations based on untrusted input may be used to perform SSRF attacks,
 * ranging from information disclosure to exposure of internal services.
 *
 * The sanitizer detects such attacks by checking if the fuzzer was able to inject the honeypot host name
 * into the requested destination. If this is the case, it reports a high severity security issue.
 *
 * That being said, if fuzzer input reaches this detector, it's likely to already trigger "slow input"
 * findings, due to trying to reach invalid hosts, before the honeypot host is requested.
 *
 * Checks are implemented via [java.net.Socket.connect] and [java.nio.channels.SocketChannel.connect] methods.
 */
@Suppress("unused_parameter", "unused")
object SsrfInjection {

    /**
     * Honeypot host name targeting an invalid address.
     * RFC 2606 defines such names at https://www.rfc-editor.org/rfc/rfc2606#section-2
     */
    private const val HONEYPOT_HOST: String = "jazzer.invalid"

    // [java.net.Socket] is used in many JDK classes to open network connections.
    // Internally it delegates to [java.net.SocketImpl], hence, for most situations
    // it's sufficient to hook the call site [java.net.Socket] itself.
    //
    // As [java.net.SocketImpl] is an abstract class all call sites invoking "connect"
    // on concrete implementations get hooked. As JKD internal classes are normally
    // ignored, they have to be marked for hooking explicitly. In this case, all
    // internal classes calling "connect" on [java.net.SocketImpl] should be listed below.
    //
    // Internal classes using [java.net.SocketImpl.connect]:
    // - java.net.Socket (hook required)
    // - java.net.AbstractPlainSocketImpl (no direct usage, no hook required)
    // - java.net.PlainSocketImpl (no direct usage, no hook required)
    // - java.net.HttpConnectSocketImpl (only used in Socket, which is already listed)
    // - java.net.SocksSocketImpl (used in Socket, but also invoking super.connect directly, hook required)
    // - java.net.ServerSocket (security check, no hook required)
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.net.SocketImpl",
        targetMethod = "connect",
        additionalClassesToHook = [
            "java.net.Socket",
            "java.net.SocksSocketImpl",
        ],
    )
    @JvmStatic
    fun checkSsrfSocket(method: MethodHandle, thisObject: Any?, arguments: Array<Any>, hookId: Int) {
        checkSsrf(arguments, hookId)
    }

    // [java.nio.channels.SocketChannel] is used in many JDK classes to open
    // (non-blocking) network connections, e.g. [java.net.http.HttpClient] uses
    // it internally.
    //
    // The actual connection is established in the abstract "connect" method.
    // Hooking that also hooks invocations of all concrete implementations,
    // from which only one exists in [sun.nio.ch.SocketChannelImpl]. "connect"
    // is only called in [java.nio.channels.SocketChannel] itself and the two
    // mentioned classes below.
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.nio.channels.SocketChannel",
        targetMethod = "connect",
        additionalClassesToHook = [
            "sun.nio.ch.SocketAdaptor",
            "jdk.internal.net.http.PlainHttpConnection",
        ],
    )
    @JvmStatic
    fun checkSsrfHttpConnection(method: MethodHandle, thisObject: Any?, arguments: Array<Any>, hookId: Int) {
        checkSsrf(arguments, hookId)
    }

    @JvmStatic
    fun checkSsrf(arguments: Array<Any>, hookId: Int) {
        if (arguments.isEmpty()) {
            return
        }

        val host = when (val arg = arguments[0]) {
            is String -> {
                try {
                    URL(arg).host
                } catch (e: MalformedURLException) {
                    null
                }
            }
            is InetAddress -> arg.hostName
            // Only implementation of java.net.SocketAddress.
            is InetSocketAddress -> arg.hostName
            else -> null
        } ?: return

        // Any connection attempt to the honeypot host is considered an SSRF.
        if (host == HONEYPOT_HOST) {
            Jazzer.reportFindingFromHook(
                FuzzerSecurityIssueHigh(
                    """
                    Server Side Request Forgery (SSRF)
                    Requests to destinations based on untrusted data could lead to exfiltration of sensitive data or exposure of internal services.
                    """.trimIndent(),
                ),
            )
        }

        // Along the way the given input is cleaned up and often results
        // in localhost. As this is not the honeypot host and not related to the
        // input anymore, return.
        if (host == "localhost") {
            return
        }

        // Some invalid characters are converted to whitespace. This seems to happen
        // mainly to linebreaks, so convert them back to better guide the fuzzer.
        // Hooking all places where the conversion happens leads to a more complex
        // solution and did not improve the fuzzer's performance to come up
        // with the honeypot host name noticeably.
        val hostname = host.replace(' ', '\n')

        Jazzer.guideTowardsEquality(hostname, HONEYPOT_HOST, 31 * hookId)
    }
}
