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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Base64;

class ValueProfileFuzzTest {
  // Only passed with the configuration parameter jazzer.valueprofile=true.
  @FuzzTest(maxDuration = "20s")
  void valueProfileFuzz(byte[] data) {
    // Trigger some coverage even with value profiling disabled.
    if (data.length < 1 || data[0] > 100) {
      return;
    }
    if (base64(data).equals("SmF6emVy")) {
      throw new FuzzerSecurityIssueMedium();
    }
  }

  private static String base64(byte[] input) {
    return Base64.getEncoder().encodeToString(input);
  }
}
