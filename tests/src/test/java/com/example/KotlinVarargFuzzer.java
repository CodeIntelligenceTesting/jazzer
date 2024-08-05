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
import java.io.IOException;

public class KotlinVarargFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws IOException {
    String out = new KotlinVararg(data.consumeRemainingAsString().split("; ")).doStuff();
    if (out.contains("a, a")) {
      throw new IOException(out);
    }
  }
}
