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

import com.code_intelligence.jazzer.api.Jazzer;

public class NoSeedFuzzer {
  public static void fuzzerInitialize() {
    // Verify that the seed was randomly generated and not taken to be the fixed
    // one set in FuzzTargetTestWrapper. This has a 1 / INT_MAX chance to be
    // flaky, which is acceptable.
    if (Jazzer.SEED == (int) 2735196724L) {
      System.err.println(
          "Jazzer.SEED should not equal the fixed seed set in FuzzTargetTestWrapper");
      System.exit(1);
    }
  }

  public static void fuzzerTestOneInput(byte[] data) {}
}
