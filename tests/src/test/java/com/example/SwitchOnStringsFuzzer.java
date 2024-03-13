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

public class SwitchOnStringsFuzzer {
  static SwitchCoverageHelper cov = new SwitchCoverageHelper(4);

  @FuzzTest
  public void test(@NotNull String data) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }
    switch (data) {
      case "The Road goes ever on and on":
        cov.coverCase(0);
        break;
      case "Out from the door where it began.":
        cov.coverCase(1);
        break;
      case "Now far ahead the Road has gone,":
        cov.coverCase(2);
        break;
      case "Let others follow it who can!":
        cov.coverCase(3);
        break;
    }
  }
}
