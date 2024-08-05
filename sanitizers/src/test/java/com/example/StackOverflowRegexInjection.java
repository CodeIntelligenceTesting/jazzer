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

/**
 * Compiling a regex pattern can lead to stack overflows and thus is caught in the constructor of
 * {@link java.util.regex.Pattern} and rethrown as a {@link java.util.regex.PatternSyntaxException}.
 * The {@link com.code_intelligence.jazzer.sanitizers.RegexInjection} sanitizer uses this exception
 * to detect injections and would incorrectly report a finding. Exceptions caused by stack overflows
 * should not be handled in the hook as it's very unlikely that the fuzzer generates a pattern
 * causing a stack overflow before it generates an invalid one.
 */
@SuppressWarnings({"ReplaceOnLiteralHasNoEffect", "ResultOfMethodCallIgnored"})
public class StackOverflowRegexInjection {
  public static void fuzzerTestOneInput(FuzzedDataProvider ignored) {
    // load regex classes by using them beforehand,
    // otherwise initialization would cause other issues.
    Pattern.compile("\n").matcher("some string").replaceAll("\\\\n");

    generatePatternSyntaxException();
  }

  @SuppressWarnings("InfiniteRecursion")
  private static void generatePatternSyntaxException() {
    // try-catch on every level to not unwind the stack
    try {
      // generate stack overflow
      generatePatternSyntaxException();
    } catch (StackOverflowError e) {
      // invoke regex injection hook
      "some sting".replaceAll("\n", "\\\\n");
    }
  }
}
