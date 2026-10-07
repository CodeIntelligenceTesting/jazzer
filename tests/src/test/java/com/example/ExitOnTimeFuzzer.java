/*
 * Copyright 2026 Code Intelligence GmbH
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

/**
 * A target with no input-dependent coverage, used to test idle coverage limits.
 *
 * <p>The optional environment variables {@code MIN_FUZZING_SECONDS} and {@code MAX_FUZZING_SECONDS}
 * bound the duration of the fuzzing run, which distinguishes an exit caused by -exit_on_time from
 * one caused by -max_total_time.
 */
public final class ExitOnTimeFuzzer {
  private static long startNanos;

  public static void fuzzerInitialize() {
    startNanos = System.nanoTime();
  }

  public static void fuzzerTestOneInput(byte[] ignored) {}

  public static void fuzzerTearDown() {
    long elapsedSeconds = (System.nanoTime() - startNanos) / 1_000_000_000L;
    String min = System.getenv("MIN_FUZZING_SECONDS");
    if (min != null && elapsedSeconds < Long.parseLong(min)) {
      throw new IllegalStateException(
          "Fuzzing stopped after " + elapsedSeconds + "s, expected at least " + min + "s");
    }
    String max = System.getenv("MAX_FUZZING_SECONDS");
    if (max != null && elapsedSeconds > Long.parseLong(max)) {
      throw new IllegalStateException(
          "Fuzzing stopped after " + elapsedSeconds + "s, expected at most " + max + "s");
    }
  }
}
