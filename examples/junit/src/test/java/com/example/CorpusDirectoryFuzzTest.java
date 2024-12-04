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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class CorpusDirectoryFuzzTest {
  private static int invocations = 0;

  @FuzzTest(maxDuration = "5s")
  public void corpusDirectoryFuzz(FuzzedDataProvider data) {
    // Throw on the third invocation to generate corpus entries.
    if (data.remainingBytes() == 0) {
      return;
    }
    // Add a few branch statements to generate different coverage.
    switch (invocations) {
      case 0:
        invocations++;
        break;
      case 1:
        invocations++;
        break;
      case 2:
        invocations++;
        break;
      case 3:
        throw new FuzzerSecurityIssueMedium();
    }
  }
}
