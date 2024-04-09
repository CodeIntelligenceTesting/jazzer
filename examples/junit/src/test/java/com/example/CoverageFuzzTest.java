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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.params.provider.ValueSource;

public class CoverageFuzzTest {
  private static long invocations = 0;

  // Fuzz target is invoked with "emptyInput" (value "0"), "ValueSource" seeds (values "1", "2",
  // "3"), plus two additional seeds (values "4" and "5") from two distinct directories.
  @ValueSource(longs = {1, 2, 3})
  @FuzzTest(maxDuration = "5s")
  public void coverage(long input) {
    invocations++;
    if (input < 0 || input > 5) {
      throw new IllegalStateException("Unexpected input value provided");
    }
  }

  @AfterAll
  public static void checkInvocations() {
    if (invocations != 6) {
      throw new IllegalStateException("Invalid number of fuzz target invocations: " + invocations);
    }
  }
}
