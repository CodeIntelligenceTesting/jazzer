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

package com.code_intelligence.jazzer.api;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiPredicate;

/** Provides static functions that configure the behavior of bug detectors provided by Jazzer. */
public final class BugDetectors {
  private static final AtomicReference<BiPredicate<String, Integer>> currentPolicy =
      getConnectionPermittedReference();

  /**
   * Allows all network connections.
   *
   * <p>See {@link #allowNetworkConnections(BiPredicate)} for an alternative that provides
   * fine-grained control over which network connections are expected.
   *
   * <p>By default, all attempted network connections are considered unexpected and result in a
   * finding being reported.
   *
   * <p>By wrapping the call into a try-with-resources statement, network connection permissions can
   * be configured to apply to individual parts of the fuzz test only:
   *
   * <pre>{@code
   * Image image = parseImage(bytes);
   * Response response;
   * try (SilentCloseable unused = BugDetectors.allowNetworkConnections()) {
   *   response = uploadImage(image);
   * }
   * handleResponse(response);
   * }</pre>
   *
   * @return a {@link SilentCloseable} that restores the previously set permissions when closed
   */
  public static SilentCloseable allowNetworkConnections() {
    return allowNetworkConnections((host, port) -> true);
  }

  /**
   * Allows all network connections for which the provided predicate returns {@code true}.
   *
   * <p>By default, all attempted network connections are considered unexpected and result in a
   * finding being reported.
   *
   * <p>By wrapping the call into a try-with-resources statement, network connection permissions can
   * be configured to apply to individual parts of the fuzz test only:
   *
   * <pre>{@code
   * Image image = parseImage(bytes);
   * Response response;
   * try (SilentCloseable unused = BugDetectors.allowNetworkConnections(
   *     (host, port) -> host.equals("example.org"))) {
   *   response = uploadImage(image, "example.org");
   * }
   * handleResponse(response);
   * }</pre>
   *
   * @param connectionPermitted a predicate that evaluate to {@code true} if network connections to
   *     the provided combination of host and port are permitted
   * @return a {@link SilentCloseable} that restores the previously set predicate when closed
   */
  public static SilentCloseable allowNetworkConnections(
      BiPredicate<String, Integer> connectionPermitted) {
    if (connectionPermitted == null) {
      throw new IllegalArgumentException("connectionPermitted must not be null");
    }
    if (currentPolicy == null) {
      throw new IllegalStateException("Failed to set network connection policy");
    }
    BiPredicate<String, Integer> previousPolicy = currentPolicy.getAndSet(connectionPermitted);
    return () -> {
      if (!currentPolicy.compareAndSet(connectionPermitted, previousPolicy)) {
        throw new IllegalStateException(
            "Failed to reset network connection policy - using try-with-resources is highly"
                + " recommended");
      }
    };
  }

  private static AtomicReference<BiPredicate<String, Integer>> getConnectionPermittedReference() {
    try {
      Class<?> ssrfSanitizer =
          Class.forName("com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery");
      return (AtomicReference<BiPredicate<String, Integer>>)
          ssrfSanitizer.getField("connectionPermitted").get(null);
    } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
      System.err.println("WARN: ");
      e.printStackTrace();
      return null;
    }
  }

  private BugDetectors() {}
}
