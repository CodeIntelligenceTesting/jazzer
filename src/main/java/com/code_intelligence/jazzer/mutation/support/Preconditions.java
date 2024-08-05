/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.support;

import static java.util.Objects.requireNonNull;

public final class Preconditions {
  private Preconditions() {}

  public static void check(boolean property) {
    if (!property) {
      throw new IllegalStateException();
    }
  }

  public static void check(boolean property, String message) {
    if (!property) {
      throw new IllegalStateException(message);
    }
  }

  public static void require(boolean property) {
    if (!property) {
      throw new IllegalArgumentException();
    }
  }

  public static void require(boolean property, String message) {
    if (!property) {
      throw new IllegalArgumentException(message);
    }
  }

  public static <T> T[] requireNonNullElements(T[] array) {
    requireNonNull(array);
    for (T element : array) {
      requireNonNull(element, "array must not contain null elements");
    }
    return array;
  }
}
