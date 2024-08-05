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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.Jazzer;

public class JazzerApiFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Jazzer.exploreState(data.consumeByte(), 1);
    Jazzer.guideTowardsEquality(data.consumeString(10), data.pickValue(new String[] {"foo"}), 1);
    Jazzer.guideTowardsEquality(data.consumeBytes(10), new byte[] {}, 2);
    Jazzer.guideTowardsContainment(data.consumeAsciiString(10), "bar", 2);
    throw new FuzzerSecurityIssueLow("Jazzer API calls succeed");
  }
}
