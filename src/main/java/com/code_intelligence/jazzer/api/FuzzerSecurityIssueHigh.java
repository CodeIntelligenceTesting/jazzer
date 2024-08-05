/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

/**
 * Thrown to indicate that a fuzz target has detected a high severity security issue rather than a
 * normal bug.
 *
 * <p>There is only a semantical but no functional difference between throwing exceptions of this
 * type or any other. However, automated fuzzing platforms can use the extra information to handle
 * the detected issues appropriately.
 */
public class FuzzerSecurityIssueHigh extends RuntimeException {
  public FuzzerSecurityIssueHigh() {}

  public FuzzerSecurityIssueHigh(String message) {
    super(message);
  }

  public FuzzerSecurityIssueHigh(String message, Throwable cause) {
    super(message, cause);
  }

  public FuzzerSecurityIssueHigh(Throwable cause) {
    super(cause);
  }
}
