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

package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;

public class ServerSideRequestForgery {
  /**
   * Honeypot host name targeting an invalid address. RFC 2606 defines such names at
   * https://www.rfc-editor.org/rfc/rfc2606#section-2
   */
  private static final String HONEYPOT_HOST = "jazzer.invalid";

  /**
   * {@link java.net.Socket} is used in many JDK classes to open network connections. Internally it
   * delegates to {@link java.net.SocketImpl}, hence, for most situations it's sufficient to hook
   * the call site {@link java.net.Socket} itself. As {@link java.net.SocketImpl} is an abstract
   * class all call sites invoking "connect" on concrete implementations get hooked. As JKD internal
   * classes are normally ignored, they have to be marked for hooking explicitly. In this case, all
   * internal classes calling "connect" on {@link java.net.SocketImpl} should be listed below.
   * Internal classes using {@link java.net.SocketImpl#connect(String, int)}:
   * <ul>
   *   <li>java.net.Socket (hook required)
   *   <li>java.net.AbstractPlainSocketImpl (no direct usage, no hook required)
   *   <li>java.net.PlainSocketImpl (no direct usage, no hook required)
   *   <li>java.net.HttpConnectSocketImpl (only used in Socket, which is already listed)
   *   <li>java.net.SocksSocketImpl (used in Socket, but also invoking super.connect directly,
   *       hook required)
   *   <li>java.net.ServerSocket (security check, no hook required)
   * </ul>
   */
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.net.SocketImpl",
      targetMethod = "connect",
      additionalClassesToHook =
          {
              "java.net.Socket",
              "java.net.SocksSocketImpl",
          })
  public static void
  checkSsrfSocket(MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkSsrf(arguments, hookId);
  }

  /**
   * {@link java.nio.channels.SocketChannel} is used in many JDK classes to open (non-blocking)
   * network connections, e.g. {@link java.net.http.HttpClient} uses it internally. The actual
   * connection is established in the abstract "connect" method. Hooking that also hooks invocations
   * of all concrete implementations, from which only one exists in {@link
   * sun.nio.ch.SocketChannelImpl}. "connect" is only called in {@link
   * java.nio.channels.SocketChannel} itself and the two mentioned classes below.
   */
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.nio.channels.SocketChannel",
      targetMethod = "connect",
      additionalClassesToHook =
          {
              "sun.nio.ch.SocketAdaptor",
              "jdk.internal.net.http.PlainHttpConnection",
          })
  public static void
  checkSsrfHttpConnection(MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkSsrf(arguments, hookId);
  }

  private static void checkSsrf(Object[] arguments, int hookId) {
    if (arguments.length == 0) {
      return;
    }

    String host;
    if (arguments[0] instanceof String) {
      try {
        host = new URL((String) arguments[0]).getHost();
      } catch (MalformedURLException e) {
        return;
      }
    } else if (arguments[0] instanceof InetAddress) {
      host = ((InetAddress) arguments[0]).getHostName();
    } else if (arguments[0] instanceof InetSocketAddress) {
      // Only implementation of java.net.SocketAddress.
      host = ((InetSocketAddress) arguments[0]).getHostName();
    } else {
      return;
    }

    // Any connection attempt to the honeypot host is considered an SSRF.
    if (HONEYPOT_HOST.equals(host)) {
      Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(
          "Server Side Request Forgery (SSRF)\nRequests to destinations based on untrusted data "
          + "could lead to exfiltration of sensitive data or exposure of internal services."));
    }

    // Along the way the given input is cleaned up and often results
    // in localhost. As this is not the honeypot host and not related to the
    // input anymore, return.
    if ("localhost".equals(host)) {
      return;
    }

    // Some invalid characters are converted to whitespace. This seems to happen
    // mainly to linebreaks, so convert them back to better guide the fuzzer.
    // Hooking all places where the conversion happens leads to a more complex
    // solution and did not improve the fuzzer's performance to come up
    // with the honeypot host name noticeably.
    String hostname = host.replace(' ', '\n');

    Jazzer.guideTowardsEquality(hostname, HONEYPOT_HOST, 31 * hookId);
  }
}
