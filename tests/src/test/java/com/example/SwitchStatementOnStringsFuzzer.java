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
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

public class SwitchStatementOnStringsFuzzer {
  static SwitchCoverageHelper cov = new SwitchCoverageHelper(4);

  @FuzzTest
  public void test(@NotNull String data) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }
    int ignored =
        switch (data) {
          case "The Road goes ever on and on" -> {
            cov.coverCase(0);
            yield 0;
          }
          case "Out from the door where it began." -> {
            cov.coverCase(1);
            yield 1;
          }
          case "Now far ahead the Road has gone," -> {
            cov.coverCase(2);
            yield 2;
          }
          case "Let others follow it who can!" -> {
            cov.coverCase(3);
            yield 3;
          }
          default -> -100;
        };
  }
}
