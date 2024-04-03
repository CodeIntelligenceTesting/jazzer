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
import java.time.LocalDateTime;

public class LocalDateTimeFuzzer {
  @FuzzTest
  void localDateTimeFuzzTest(LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return;
    }
    LocalDateTime targetDate = LocalDateTime.of(2024, 5, 30, 23, 59);
    if (targetDate.getDayOfYear() == localDateTime.getDayOfYear()) {
      throw new FuzzerSecurityIssueLow("LocalDateTime mutator works!");
    }
  }
}
