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

import java.time.Instant;

public class CrashResistantCoverageTarget {
  public static void fuzzerTestOneInput(byte[] data) {
    if (data.length < 10) {
      // Crash immediately on the empty and the first seed input so that we can verify that the
      // crash-resistant merge strategy actually works.
      throw new IllegalStateException("Crash");
    }
    if (data.length < 100) {
      someFunction();
    }
  }

  public static void someFunction() {
    // A non-trivial condition that always evaluates to true.
    if (Instant.now().getNano() >= 0) {
      System.out.println("Hello, world!");
    }
  }
}
