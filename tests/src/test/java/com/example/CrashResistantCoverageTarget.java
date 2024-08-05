/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import java.time.Instant;

public class CrashResistantCoverageTarget {
  public static void fuzzerTestOneInput(byte[] data) {
    if (data.length < 10) {
      // Crash immediately on the empty and the first seed input so that we can verify that the
      // crash-resistant merge strategy actually works.
      throw new IllegalStateException("Crash");
    }
    if (data.length < 100) {
      someFunction();
    }
  }

  public static void someFunction() {
    // A non-trivial condition that always evaluates to true.
    if (Instant.now().getNano() >= 0) {
      System.out.println("Hello, world!");
    }
  }
}
