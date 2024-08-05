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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.google.json.JsonSanitizer;

public class JsonSanitizerDenylistFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    String validJson;
    try {
      validJson = JsonSanitizer.sanitize(input, 10);
    } catch (Exception e) {
      return;
    }

    // Check for forbidden substrings. As these would enable Cross-Site Scripting, treat every
    // finding as a high severity vulnerability.
    assert !validJson.contains("</script")
        : new FuzzerSecurityIssueHigh("Output contains </script");
    assert !validJson.contains("]]>") : new FuzzerSecurityIssueHigh("Output contains ]]>");

    // Check for more forbidden substrings. As these would not directly enable Cross-Site Scripting
    // in general, but may impact script execution on the embedding page, treat each finding as a
    // medium severity vulnerability.
    assert !validJson.contains("<script")
        : new FuzzerSecurityIssueMedium("Output contains <script");
    assert !validJson.contains("<!--") : new FuzzerSecurityIssueMedium("Output contains <!--");
  }
}
