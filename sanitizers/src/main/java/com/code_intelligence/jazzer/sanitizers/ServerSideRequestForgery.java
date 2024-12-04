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

package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiPredicate;

public class ServerSideRequestForgery {
  // Set via reflection by Jazzer's BugDetectors API.
  // Allow connections to all hosts and ports until before a fuzz target is executed for the first
  // time. This allows the fuzzing setup to connect anywhere without triggering an SSRF-finding
  // during initialization.
  public static final AtomicReference<BiPredicate<String, Integer>> connectionPermitted =
      new AtomicReference<>((host, port) -> true);

  // Disallow all connections right before the first fuzz target is executed.
  static {
    Jazzer.onFuzzTargetReady(() -> connectionPermitted.set((host, port) -> false));
  }

  /**
   * {@link java.net.Socket} is used in many JDK classes to open network connections. Internally it
   * delegates to {@link java.net.SocketImpl}, hence, for most situations it's sufficient to hook
   * the call site {@link java.net.Socket} itself. As {@link java.net.SocketImpl} is an abstract
   * class all call sites invoking "connect" on concrete implementations get hooked. As JKD internal
   * classes are normally ignored, they have to be marked for hooking explicitly. In this case, all
   * internal classes calling "connect" on {@link java.net.SocketImpl} should be listed below.
   * Internal classes using {@link java.net.SocketImpl#connect(String, int)}:
   *
   * <ul>
   *   <li>java.net.Socket (hook required)
   *   <li>java.net.AbstractPlainSocketImpl (no direct usage, no hook required)
   *   <li>java.net.PlainSocketImpl (no direct usage, no hook required)
   *   <li>java.net.HttpConnectSocketImpl (only used in Socket, which is already listed)
   *   <li>java.net.SocksSocketImpl (used in Socket, but also invoking super.connect directly, hook
   *       required)
   *   <li>java.net.ServerSocket (security check, no hook required)
   * </ul>
   */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.net.SocketImpl",
      targetMethod = "connect",
      additionalClassesToHook = {
        "java.net.Socket",
        "java.net.SocksSocketImpl",
      })
  public static void checkSsrfSocket(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkSsrf(arguments);
  }

  /**
   * {@link java.nio.channels.SocketChannel} is used in many JDK classes to open (non-blocking)
   * network connections, e.g. {@link java.net.http.HttpClient} uses it internally. The actual
   * connection is established in the abstract "connect" method. Hooking that also hooks invocations
   * of all concrete implementations, from which only one exists in {@link
   * sun.nio.ch.SocketChannelImpl}. "connect" is only called in {@link
   * java.nio.channels.SocketChannel} itself and the two mentioned classes below.
   */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.nio.channels.SocketChannel",
      targetMethod = "connect",
      additionalClassesToHook = {
        "sun.nio.ch.SocketAdaptor",
        "jdk.internal.net.http.PlainHttpConnection",
      })
  public static void checkSsrfHttpConnection(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkSsrf(arguments);
  }

  private static void checkSsrf(Object[] arguments) {
    if (arguments.length == 0) {
      return;
    }

    String host;
    int port;
    if (arguments[0] instanceof InetSocketAddress) {
      // Only implementation of java.net.SocketAddress.
      InetSocketAddress address = (InetSocketAddress) arguments[0];
      host = address.getHostName();
      port = address.getPort();
    } else if (arguments.length >= 2 && arguments[1] instanceof Integer) {
      if (arguments[0] instanceof InetAddress) {
        host = ((InetAddress) arguments[0]).getHostName();
      } else if (arguments[0] instanceof String) {
        host = (String) arguments[0];
      } else {
        return;
      }
      port = (int) arguments[1];
    } else {
      return;
    }

    if (port < 0 || port > 65535) {
      return;
    }

    if (!connectionPermitted.get().test(host, port)) {
      Jazzer.reportFindingFromHook(
          new FuzzerSecurityIssueMedium(
              String.format(
                  "Server Side Request Forgery (SSRF)\n"
                      + "Attempted connection to: %s:%d\n"
                      + "Requests to destinations based on untrusted data could lead to"
                      + " exfiltration of sensitive data or exposure of internal services.\n\n"
                      + "If the fuzz test is expected to perform network connections, call"
                      + " com.code_intelligence.jazzer.api.BugDetectors#allowNetworkConnections at"
                      + " the beginning of your fuzz test and optionally provide a predicate"
                      + " matching the expected hosts.",
                  host, port)));
    }
  }
}
