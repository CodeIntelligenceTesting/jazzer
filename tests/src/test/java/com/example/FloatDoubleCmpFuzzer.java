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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class FloatDoubleCmpFuzzer {
  @FuzzTest
  void floatDoubleCmp(float f, double d) {
    float fx = f * f - 8.625f * f;
    double dx = d * d - 10.8125 * d;
    if (fx == -12.65625f && dx == -24.3046875) {
      throw new FuzzerSecurityIssueLow("Float/double comparison tracking works!");
    }
  }
}
