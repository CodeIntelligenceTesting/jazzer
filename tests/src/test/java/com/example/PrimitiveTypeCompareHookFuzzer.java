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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;

/*
 * Regression test for https://github.com/CodeIntelligenceTesting/jazzer/issues/790.
 */
public class PrimitiveTypeCompareHookFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Byte.compare(data.consumeByte(), (byte) 127);
    Short.compare(data.consumeShort(), (short) 4096);
    throw new FuzzerSecurityIssueCritical();
  }
}
