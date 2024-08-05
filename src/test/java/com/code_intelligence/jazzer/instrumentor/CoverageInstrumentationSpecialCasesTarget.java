/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

import java.util.Random;

public class CoverageInstrumentationSpecialCasesTarget {
  public ReturnClass newAfterJump() {
    if (new Random().nextBoolean()) {
      throw new RuntimeException("");
    }
    return new ReturnClass(new Random().nextBoolean() ? "foo" : "bar");
  }

  public int newAndTryCatch() {
    new Random();
    try {
      new Random();
      return 2;
    } catch (RuntimeException e) {
      new Random();
      return 1;
    }
  }

  public static class ReturnClass {
    public ReturnClass(String content) {}
  }
}
