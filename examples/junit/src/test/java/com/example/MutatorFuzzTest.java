/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.code_intelligence.jazzer.driver.FuzzTargetRunner;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.util.List;
import org.junit.jupiter.api.AfterAll;

class MutatorFuzzTest {
  @FuzzTest
  void mutatorFuzz(List<@NotNull String> list) {
    // Check that the mutator is actually doing something.
    if (list != null && list.size() > 3 && list.get(2).equals("mutator")) {
      throw new AssertionError("Found expected JUnit mutator test issue");
    }
  }

  @AfterAll
  static void assertFuzzTargetRunner() {
    // FuzzTargetRunner values are not set in JUnit engine tests.
    String jazzerFuzz = System.getenv("JAZZER_FUZZ");
    if (jazzerFuzz != null && !jazzerFuzz.isEmpty()) {
      assertEquals(FuzzTargetRunner.mutatorDebugString(), "Arguments[Nullable<List<String>>]");
    }
  }
}
