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

public class RegexCanonEqInjection {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    try {
      Pattern.compile(Pattern.quote(input), Pattern.CANON_EQ);
    } catch (PatternSyntaxException ignored) {
    } catch (IllegalArgumentException ignored) {
      // "[媼" generates an IllegalArgumentException but only on Windows using
      // Java 8. We ignore this for now.
      //
      // java.lang.IllegalArgumentException
      //	at java.lang.AbstractStringBuilder.appendCodePoint(AbstractStringBuilder.java:800)
      //	at java.lang.StringBuilder.appendCodePoint(StringBuilder.java:240)
      //	at java.util.regex.Pattern.normalizeCharClass(Pattern.java:1430)
      //	at java.util.regex.Pattern.normalize(Pattern.java:1396)
      //	at java.util.regex.Pattern.compile(Pattern.java:1665)
      //	at java.util.regex.Pattern.<init>(Pattern.java:1352)
      //	at java.util.regex.Pattern.compile(Pattern.java:1054)
    }
  }
}
