/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import java.math.BigDecimal;

public class ExampleStackOverflowFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    step1();
  }

  private static void step1() {
    BigDecimal unused = BigDecimal.valueOf(10, 100);
    step2();
  }

  private static void step2() {
    boolean unused = "foobar".contains("bar");
    step1();
  }
}
