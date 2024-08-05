/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.Jazzer;

public class NoSeedFuzzer {
  public static void fuzzerInitialize() {
    // Verify that the seed was randomly generated and not taken to be the fixed
    // one set in FuzzTargetTestWrapper. This has a 1 / INT_MAX chance to be
    // flaky, which is acceptable.
    if (Jazzer.SEED == (int) 2735196724L) {
      System.err.println(
          "Jazzer.SEED should not equal the fixed seed set in FuzzTargetTestWrapper");
      System.exit(1);
    }
  }

  public static void fuzzerTestOneInput(byte[] data) {}
}
