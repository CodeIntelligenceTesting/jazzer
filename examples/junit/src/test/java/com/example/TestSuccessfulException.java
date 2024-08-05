/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

/**
 * An exception thrown by a java_fuzz_target_test if the test run is considered successful.
 *
 * <p>Use this instead of a generic exception to ensure that tests do not pass if such a generic
 * exception is thrown unexpectedly.
 *
 * <p>Use this instead of {@link com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow} and other
 * Jazzer-specific exceptions as using them in tests leads to classloader issues: The exception
 * classes may be loaded both in the bootstrap and the system classloader depending on when exactly
 * the agent (and with it the bootstrap jar) is installed, which can cause in `instanceof` checks
 * failing unexpectedly.
 */
public class TestSuccessfulException extends Exception {
  public TestSuccessfulException(String message) {
    super(message);
  }
}
