/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import java.util.List;

public final class ListOfIntegersFuzzer {
  public static void fuzzerTestOneInput(
      @NotNull @WithSize(min = 10, max = 10) List<@NotNull Integer> data) {
    if (data.size() != 10) return;

    if (data.get(0) == 10) {
      if (data.get(1) == 200000) {
        if (data.get(2) == 300000) {
          if (data.get(3) == 102031) {
            if (data.get(4) == 918736) {
              if (data.get(5) == 12301) {
                throw new TreasureFoundException();
              }
            }
          }
        }
      }
    }
  }

  private static class TreasureFoundException extends RuntimeException {}
}
