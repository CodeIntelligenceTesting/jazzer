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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import java.security.SecureRandom;

public class ExampleFuzzer {
  public static void fuzzerInitialize() {
    // Optional initialization to be run before the first call to fuzzerTestOneInput.
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    // Without the hook in ExampleFuzzerHooks.java, the value of random would change on every
    // invocation, making it almost impossible to guess for the fuzzer.
    long random = new SecureRandom().nextLong();
    if (input.startsWith("magicstring" + random)
        && input.length() > 30
        && input.charAt(25) == 'C') {
      mustNeverBeCalled();
    }
  }

  private static void mustNeverBeCalled() {
    throw new FuzzerSecurityIssueMedium("mustNeverBeCalled has been called");
  }
}
