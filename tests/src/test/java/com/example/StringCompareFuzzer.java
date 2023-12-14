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
import java.util.Base64;

public class StringCompareFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    String text = Base64.getEncoder().encodeToString(data);
    if (text.startsWith("aGVsbG8K") // hello
        && text.endsWith("d29ybGQK") // world
    ) {
      throw new FuzzerSecurityIssueLow("Found the secret message!");
    }
  }
}
