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

class AutofuzzFuzzTest {
  private static class IntHolder {
    private final int i;

    IntHolder(int i) {
      this.i = i;
    }

    public int getI() {
      return i;
    }
  }

  @FuzzTest(maxDuration = "5m")
  void autofuzz(String str, IntHolder holder) {
    assumeTrue(holder != null);
    if (holder.getI() == 1234 && str != null && str.contains("jazzer")) {
      throw new RuntimeException();
    }
  }
}
