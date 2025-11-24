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
import com.code_intelligence.jazzer.mutation.annotation.InRange;

public class CharFuzzer {
  private static final char min = '中' - 10;
  private static final char max = '中' + 10;

  public static void fuzzerTestOneInput(@InRange(min = min, max = max) char data) {
    if (data < min || data > max) {
      throw new RuntimeException("Char out of range: " + (int) data);
    }
    if (data == '中') {
      throw new FuzzerSecurityIssueLow("Found the 'secret' char!");
    }
  }
}
