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
