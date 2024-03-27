/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.junit.FuzzTest;

public class InitializationErrorTest {

  static {
    sneakyThrow();
  }

  private static void sneakyThrow() {
    throw new IllegalArgumentException("Sneaky throw in static initializer");
  }

  @FuzzTest
  public void fuzz(String ignored) {
    throw new IllegalStateException("This method should not be executed");
  }
}
