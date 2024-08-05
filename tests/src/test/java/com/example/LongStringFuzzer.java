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

/**
 * Provoke a finding with huge captured data to verify that the generated crash reproducer is still
 * compilable. This test uses a huge, predefined corpus to speed up finding the issue.
 *
 * <p>Reproduces issue #269 (<a
 * href="https://github.com/CodeIntelligenceTesting/jazzer/issues/269">...</a>)
 */
public class LongStringFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    if (data.length > 1024 * 64) {
      throw new FuzzerSecurityIssueLow("String too long exception");
    }
  }
}
