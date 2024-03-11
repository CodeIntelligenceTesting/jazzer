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
import com.code_intelligence.jazzer.junit.FuzzTest;

public class RegressionModeTest {

  private static int count = 0;

  @FuzzTest
  void fuzzTest(String ignored) {
    if (count++ > 0) {
      throw new FuzzerSecurityIssueLow("Should not be reached in regression mode");
    }
  }
}
