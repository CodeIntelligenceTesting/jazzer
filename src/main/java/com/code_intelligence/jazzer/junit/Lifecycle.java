/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

/** Possible values for the {@link FuzzTest#lifecycle()} option. */
public enum Lifecycle {
  /**
   * Fuzz tests with this lifecycle only go through the JUnit test method lifecycle once during
   * fuzzing, i.e., per-test lifecycle methods such as {@link org.junit.jupiter.api.BeforeEach}
   * methods are executed once for each fuzz test.
   *
   * <p>This mode is usually more efficient than {@link Lifecycle#PER_EXECUTION}, but is more likely
   * to unintentionally preserve state between fuzz test executions, which can result in
   * non-reproducible findings.
   */
  PER_TEST,

  /**
   * Fuzz tests with this lifecycle go through the JUnit test method lifecycle once for every test
   * method execution during fuzzing, i.e., per-test lifecycle methods such as {@link
   * org.junit.jupiter.api.BeforeEach} methods are executed before each individual invocation of the
   * fuzz test method and every execution uses its own test class instance.
   *
   * <p>This mode is usually less efficient than {@link Lifecycle#PER_TEST}, but makes it easier to
   * write stateless fuzz tests that interoperate correctly with JUnit extensions used by test
   * frameworks.
   *
   * <p>The following lifecycle methods and extensions are currently supported:
   *
   * <ul>
   *   <li>{@link org.junit.jupiter.api.extension.BeforeEachCallback}
   *   <li>{@link org.junit.jupiter.api.extension.TestInstancePostProcessor}
   *   <li>{@link org.junit.jupiter.api.BeforeEach}
   *   <li>{@link org.junit.jupiter.api.AfterEach}
   *   <li>{@link org.junit.jupiter.api.extension.AfterEachCallback}
   * </ul>
   *
   * <p>Note: Lifecycle methods for different test class instances may be invoked concurrently,
   * which can lead to issues if these methods are using global resources (e.g. file locks).
   */
  PER_EXECUTION,
}
