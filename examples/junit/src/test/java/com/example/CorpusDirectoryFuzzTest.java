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

public class CorpusDirectoryFuzzTest {
  private static int invocations = 0;

  @FuzzTest(maxDuration = "5s")
  public void corpusDirectoryFuzz(FuzzedDataProvider data) {
    // Throw on the third invocation to generate corpus entries.
    if (data.remainingBytes() == 0) {
      return;
    }
    // Add a few branch statements to generate different coverage.
    switch (invocations) {
      case 0:
        invocations++;
        break;
      case 1:
        invocations++;
        break;
      case 2:
        invocations++;
        break;
      case 3:
        throw new FuzzerSecurityIssueMedium();
    }
  }
}
