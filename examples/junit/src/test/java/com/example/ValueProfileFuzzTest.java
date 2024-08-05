/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Base64;

class ValueProfileFuzzTest {
  // Only passed with the configuration parameter jazzer.valueprofile=true.
  @FuzzTest(maxDuration = "20s")
  void valueProfileFuzz(byte[] data) {
    // Trigger some coverage even with value profiling disabled.
    if (data.length < 1 || data[0] > 100) {
      return;
    }
    if (base64(data).equals("SmF6emVy")) {
      throw new FuzzerSecurityIssueMedium();
    }
  }

  private static String base64(byte[] input) {
    return Base64.getEncoder().encodeToString(input);
  }
}
