/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

public class ExampleOutOfMemoryFuzzer {
  public static long[] leak;

  public static void fuzzerTestOneInput(byte[] input) {
    if (input.length == 0) {
      return;
    }
    leak = new long[Integer.MAX_VALUE];
  }
}
