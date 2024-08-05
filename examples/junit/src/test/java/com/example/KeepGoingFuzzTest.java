/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.junit.FuzzTest;

public class KeepGoingFuzzTest {
  private static int counter = 0;

  @FuzzTest
  public void keepGoingFuzzTest(byte[] ignored) {
    counter++;
    if (counter == 1) {
      throw new IllegalArgumentException("error1");
    }
    if (counter == 2) {
      throw new IllegalArgumentException("error2");
    }
  }
}
