/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

// An exception wrapping a {@link Throwable} thrown during the actual invocation of, but not the
// construction of parameters for an autofuzzed method.
/** Only used internally. */
public class AutofuzzInvocationException extends RuntimeException {
  public AutofuzzInvocationException() {
    super();
  }

  public AutofuzzInvocationException(Throwable cause) {
    super(cause);
  }
}
