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

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.function.Supplier;

/** Provides static functions that configure the behavior of bug detectors provided by Jazzer. */
public final class BugDetectors {
  private static final AtomicReference<BiPredicate<String, Integer>> currentPolicy =
      getSanitizerVariable(
          "com.code_intelligence.jazzer.sanitizers.ServerSideRequestForgery",
          "connectionPermitted");

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
    return setSanitizerVariable(connectionPermitted, currentPolicy);
  }

  // File path traversal sanitizer control
  private static final AtomicReference<Supplier<Path>> currentPathTraversalTarget =
      getSanitizerVariable("com.code_intelligence.jazzer.sanitizers.FilePathTraversal", "target");

  /**
   * Sets the target for file path traversal sanitization. If the target is reached, a finding is
   * thrown. The target is also used to guide the fuzzer to intentionally trigger file path
   * traversal.
   *
   * <p>By default, the file path traversal target is set to return {@code "../jazzer-traversal"}.
   *
   * <p>Setting the path traversal target supplier to return {@code null } will disable the
   * guidance.
   *
   * <p>By wrapping the call into a try-with-resources statement, the target can be configured to
   * apply to individual parts of the fuzz test only:
   *
   * <pre>{@code
   * try (SilentCloseable unused = BugDetectors.setFilePathTraversalTarget(() -> Paths.get("/root"))) {
   *   // Perform operations that require file path traversal sanitization
   * }
   * }</pre>
   *
   * @param pathTraversalTarget a supplier that provides the target directory for file path
   *     traversal sanitization
   * @return a {@link SilentCloseable} that restores the previously set target when closed
   */
  public static SilentCloseable setFilePathTraversalTarget(Supplier<Path> pathTraversalTarget) {
    return setSanitizerVariable(pathTraversalTarget, currentPathTraversalTarget);
  }

  private static final AtomicReference<Predicate<Path>> currentCheckPath =
      getSanitizerVariable(
          "com.code_intelligence.jazzer.sanitizers.FilePathTraversal", "checkPath");

  /**
   * Sets the predicate that determines if a file path is allowed to be accessed. Paths that are not
   * allowed will trigger a file path traversal finding. If you use this method, don't forget to set
   * the fuzzing target with {@code setFilePathTraversalTarget} that aligns with this predicate,
   * because both {@code target} and {@code checkPath} can trigger a finding independently.
   *
   * <p>By default, all file paths are allowed. Setting the predicate to {@code false} will trigger
   * a file path traversal finding for any file path access.
   *
   * <p>By wrapping the call into a try-with-resources statement, the predicate can be configured to
   * apply to individual parts of the fuzz test only:
   *
   * <pre>{@code
   * try (SilentCloseable unused = BugDetectors.setFilePathTraversalAllowPath(
   *     (Path p) -> p.toString().contains("secret"))) {
   *   // Perform operations that require file path traversal sanitization
   * }
   * }</pre>
   *
   * @param checkPath a predicate that evaluates to {@code true} if the file path is allowed
   * @return a {@link SilentCloseable} that restores the previously set predicate when closed
   */
  public static SilentCloseable setFilePathTraversalAllowPath(Predicate<Path> checkPath) {
    return setSanitizerVariable(checkPath, currentCheckPath);
  }

  private static <T> AtomicReference<T> getSanitizerVariable(
      String sanitizerClassName, String fieldName) {
    try {
      return (AtomicReference<T>) Class.forName(sanitizerClassName).getField(fieldName).get(null);
    } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
      System.err.println("WARN: ");
      e.printStackTrace();
      return null;
    }
  }

  private static <T> SilentCloseable setSanitizerVariable(
      T newValue, AtomicReference<T> currentValue) {
    if (newValue == null) {
      throw new IllegalArgumentException("sanitizer variable must not be null");
    }
    if (currentValue == null) {
      throw new IllegalStateException("Failed to set sanitizer variable");
    }
    T previousValue = currentValue.getAndSet(newValue);
    return () -> {
      if (!currentValue.compareAndSet(newValue, previousValue)) {
        throw new IllegalStateException(
            "Failed to reset sanitizer variable - using try-with-resources is highly"
                + " recommended");
      }
    };
  }

  private BugDetectors() {}
}
