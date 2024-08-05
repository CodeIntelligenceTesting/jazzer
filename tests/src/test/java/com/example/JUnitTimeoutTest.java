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
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.time.Instant;
import org.junit.jupiter.api.Timeout;

class JUnitTimeoutTest {

  @Retention(RetentionPolicy.RUNTIME)
  @FuzzTest
  @Timeout(3)
  public @interface TimedFuzzTest {}

  private static int runs = 0;

  @TimedFuzzTest
  void timesOutTest(byte[] data) throws InterruptedException {
    if (runs++ > 0) {
      return;
    }

    Instant start = Instant.now();
    Instant end = start.plusSeconds(10);
    while (Instant.now().isBefore(end)) {
      // JUnit's timeout handling would interrupt this sleep if active.
      Thread.sleep(50);
    }
    // Neither JUnit's nor libFuzzer's timeout handling applied.
  }
}
