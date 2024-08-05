/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static org.junit.jupiter.api.Assertions.fail;

import com.code_intelligence.jazzer.junit.FuzzTest;

class ByteFuzzTest {
  @FuzzTest
  void byteFuzz(byte[] data) {
    if (data.length < 1) {
      return;
    }
    if (data[0] % 2 == 0) {
      fail();
    }
  }
}
