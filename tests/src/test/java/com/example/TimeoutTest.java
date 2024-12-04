/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
