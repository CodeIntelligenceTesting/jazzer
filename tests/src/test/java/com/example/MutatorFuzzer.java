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
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

public class MutatorFuzzer {
  public static void fuzzerTestOneInput(
      @InRange(max = -42) short num, @NotNull SimpleProto.MyProto proto) {
    if (num > -42) {
      throw new IllegalArgumentException();
    }

    if (proto.getNumber() == 12345678) {
      if (proto.getMessage().getText().contains("Hello, proto!")) {
        throw new FuzzerSecurityIssueMedium("Dangerous proto");
      }
    }
  }
}
