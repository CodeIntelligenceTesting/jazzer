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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class SwitchStatementOnIntegersFuzzer {
  private static SwitchCoverageHelper cov = new SwitchCoverageHelper(5);

  @FuzzTest
  public void test(int data) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }

    int ignored =
        switch (data) {
          case 19391 -> {
            cov.coverCase(0);
            yield 0;
          }
          case 1101010 -> {
            cov.coverCase(1);
            yield 1;
          }
          case 23202020 -> {
            cov.coverCase(2);
            yield 2;
          }
          case 333003033 -> {
            cov.coverCase(3);
            yield 3;
          }
          case 429102931 -> {
            cov.coverCase(4);
            yield 4;
          }
          default -> -10;
        };
  }
}
