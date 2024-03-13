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

public class SwitchMultipleCaseLabelsOfStrings {
  static SwitchCoverageHelper cov = new SwitchCoverageHelper(4);

  @FuzzTest
  public void test(@NotNull String data) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }
    String ignored =
        switch (data) {
          case "Test1", "Blidfsfba", "BUIbda1ibeb", "nfbuidsf91" -> {
            cov.coverCase(0);
            yield "Hello 0";
          }
          case "Olqofdsn", "ndsufi298fnbds", "fndsjaf" -> {
            cov.coverCase(1);
            yield "Hello 1";
          }
          case "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" -> {
            cov.coverCase(2);
            yield "Hello 2";
          }
          case "Unknown", "Unknown2", "Unknown3" -> {
            cov.coverCase(3);
            yield "Hello 3";
          }
          default -> "Hello default";
        };
  }
}
