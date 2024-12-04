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
import java.security.SecureRandom;

public class ExampleFuzzer {
  public static void fuzzerInitialize() {
    // Optional initialization to be run before the first call to fuzzerTestOneInput.
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    // Without the hook in ExampleFuzzerHooks.java, the value of random would change on every
    // invocation, making it almost impossible to guess for the fuzzer.
    long random = new SecureRandom().nextLong();
    if (input.startsWith("magicstring" + random)
        && input.length() > 30
        && input.charAt(25) == 'C') {
      mustNeverBeCalled();
    }
  }

  private static void mustNeverBeCalled() {
    throw new FuzzerSecurityIssueMedium("mustNeverBeCalled has been called");
  }
}
