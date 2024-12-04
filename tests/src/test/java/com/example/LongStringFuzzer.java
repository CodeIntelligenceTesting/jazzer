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

/**
 * Provoke a finding with huge captured data to verify that the generated crash reproducer is still
 * compilable. This test uses a huge, predefined corpus to speed up finding the issue.
 *
 * <p>Reproduces issue #269 (<a
 * href="https://github.com/CodeIntelligenceTesting/jazzer/issues/269">...</a>)
 */
public class LongStringFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    if (data.length > 1024 * 64) {
      throw new FuzzerSecurityIssueLow("String too long exception");
    }
  }
}
