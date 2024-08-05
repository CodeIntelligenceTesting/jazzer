/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class DirectoryInputsFuzzTest {
  private static boolean firstSeed = true;

  @FuzzTest(maxDuration = "0s")
  public void inputsFuzz(FuzzedDataProvider data) {
    // Only execute the fuzz test logic on the empty input and the only seed.
    if (data.remainingBytes() == 0) {
      return;
    }
    String input = data.consumeRemainingAsString();
    if (!firstSeed && !input.equals("directory")) {
      throw new IllegalStateException("Should have crashed on the first non-empty input");
    }
    firstSeed = false;
    if (input.equals("directory")) {
      throw new FuzzerSecurityIssueMedium();
    }
  }
}
