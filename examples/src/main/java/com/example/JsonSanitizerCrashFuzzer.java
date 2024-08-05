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
import com.google.json.JsonSanitizer;

public class JsonSanitizerCrashFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    try {
      JsonSanitizer.sanitize(input, 10);
    } catch (ArrayIndexOutOfBoundsException ignored) {
      // ArrayIndexOutOfBoundsException is expected if nesting depth is
      // exceeded.
    }
  }
}
