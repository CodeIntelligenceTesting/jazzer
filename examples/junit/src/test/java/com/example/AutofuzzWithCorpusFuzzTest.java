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

class AutofuzzWithCorpusFuzzTest {
  @FuzzTest
  void autofuzzWithCorpus(String str, int i) {
    if ("jazzer".equals(str) && i == 1234) {
      throw new RuntimeException();
    }
  }
}
