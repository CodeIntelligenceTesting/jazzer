/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

// An exception wrapping a Throwable thrown during the construction of parameters for, but not the
// actual invocation of an autofuzzed method.
/** Only used internally. */
public class AutofuzzConstructionException extends RuntimeException {
  public AutofuzzConstructionException() {
    super();
  }

  public AutofuzzConstructionException(String message) {
    super(message);
  }

  public AutofuzzConstructionException(Throwable cause) {
    super(cause);
  }
}
