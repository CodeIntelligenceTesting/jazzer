/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.support;

public final class ExceptionSupport {
  /**
   * Allows throwing any {@link Throwable} unchanged as if it were an unchecked exception.
   *
   * <p>Example: {@code throw asUnchecked(new IOException())}
   */
  @SuppressWarnings("unchecked")
  public static <T extends Throwable> T asUnchecked(Throwable t) throws T {
    throw (T) t;
  }

  private ExceptionSupport() {}
}
