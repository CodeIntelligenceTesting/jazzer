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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class RegexInsecureQuoteInjection {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    try {
      Pattern.matches("\\Q" + input + "\\E", "foobar");
    } catch (PatternSyntaxException ignored) {
    }
  }
}
