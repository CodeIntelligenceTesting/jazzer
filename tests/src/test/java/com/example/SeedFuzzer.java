/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.Jazzer;

public class SeedFuzzer {
  public static void fuzzerInitialize() {
    if (Jazzer.SEED != 1234567) {
      throw new FuzzerSecurityIssueLow("Expected Jazzer.SEED to be 1234567, got " + Jazzer.SEED);
    }
  }

  public static void fuzzerTestOneInput(byte[] data) {}
}
