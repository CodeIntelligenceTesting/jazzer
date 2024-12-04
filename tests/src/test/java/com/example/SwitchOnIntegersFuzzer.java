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

public class SwitchOnIntegersFuzzer {
  static SwitchCoverageHelper cov = new SwitchCoverageHelper(5);

  @FuzzTest
  public void test(int data) {
    if (cov.allBranchesCovered()) {
      throw new FuzzerSecurityIssueLow("All cases visited");
    }

    switch (data) {
      case 1029391:
        cov.coverCase(0);
        break;
      case 10101010:
        cov.coverCase(1);
        break;
      case 20202020:
        cov.coverCase(2);
        break;
      case 303003033:
        cov.coverCase(3);
        break;
      case 409102931:
        cov.coverCase(4);
        break;
      default:
        break;
    }
  }
}
