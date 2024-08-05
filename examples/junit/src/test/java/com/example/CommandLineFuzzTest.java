/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;

class CommandLineFuzzTest {
  int run = 0;

  @FuzzTest
  void commandLineFuzz(byte[] bytes) {
    assumeTrue(bytes.length > 0);
    switch (run++) {
      case 0:
        throw new RuntimeException();
      case 1:
        throw new IllegalStateException();
      case 2:
        throw new Error();
    }
  }
}
