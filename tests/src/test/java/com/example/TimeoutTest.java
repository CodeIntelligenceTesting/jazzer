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
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Timeout;

public class TimeoutTest {

  @FuzzTest
  @Timeout(5)
  @SuppressWarnings("InfiniteLoopStatement")
  public void timeout(String ignored) throws InterruptedException {
    while (true) {
      // JUnit supports different thread modes in the timeout context, see
      // https://junit.org/junit5/docs/current/user-guide/#writing-tests-declarative-timeouts-thread-mode
      //
      // As a result it can not detect infinite busy loops in the default thread mode.
      // For this it would be necessary to switch the thread mode from SAME_THREAD to
      // SEPARATE_THREAD, so that the second thread could detect timeout in the first one executing
      // the actual test. It is possible to detect timeouts in "not busy" infinite loops, though.
      // These release their possession of a thread via JVM concurrency functions, e.g. sleep, wait,
      // etc.
      //
      // This differs from fuzzing mode, in which JUnit timeout handling is deactivated and timeouts
      // are solely handled by libFuzzer. libFuzzer registers reoccurring alarm handlers to detect
      // timeouts in the fuzzer process. This approach is comparable to the SEPARATE_THREAD mode in
      // JUnit.
      TimeUnit.SECONDS.sleep(1);
    }
  }
}
