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
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.util.Map;

public class MapFuzzer {
  public static void fuzzerTestOneInput(@NotNull Map<@NotNull String, @NotNull String> map) {
    if (map.getOrDefault("some_key", "").startsWith("prefix")) {
      if (map.containsKey("other_key")) {
        throw new FuzzerSecurityIssueMedium();
      }
    }
  }
}
