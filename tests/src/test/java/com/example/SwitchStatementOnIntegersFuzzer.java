/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class SwitchStatementOnIntegersFuzzer {
  private static SwitchCoverageHelper cov = new SwitchCoverageHelper(5);

  @FuzzTest
  public void test(int data) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }

    int ignored =
        switch (data) {
          case 19391 -> {
            cov.coverCase(0);
            yield 0;
          }
          case 1101010 -> {
            cov.coverCase(1);
            yield 1;
          }
          case 23202020 -> {
            cov.coverCase(2);
            yield 2;
          }
          case 333003033 -> {
            cov.coverCase(3);
            yield 3;
          }
          case 429102931 -> {
            cov.coverCase(4);
            yield 4;
          }
          default -> -10;
        };
  }
}
