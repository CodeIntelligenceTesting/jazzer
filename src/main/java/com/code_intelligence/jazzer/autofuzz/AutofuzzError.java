/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.autofuzz;

/** An error indicating an internal error in the autofuzz functionality. */
public class AutofuzzError extends Error {
  private static final String MESSAGE_TRAILER =
      String.format(
          "%nPlease file an issue at:%n "
              + " https://github.com/CodeIntelligenceTesting/jazzer/issues/new/choose");

  public AutofuzzError(String message) {
    super(message + MESSAGE_TRAILER);
  }

  public AutofuzzError(String message, Throwable cause) {
    super(message + MESSAGE_TRAILER, cause);
  }
}
