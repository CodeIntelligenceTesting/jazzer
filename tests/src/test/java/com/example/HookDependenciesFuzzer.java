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
import java.util.regex.Pattern;

// This fuzzer verifies that:
// 1. a class referenced in a static initializer of a hook is still instrumented with the hook;
// 2. hooks that are not shipped in the Jazzer agent JAR can still instrument Java standard library
//    classes.
public class HookDependenciesFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    try {
      Pattern.matches("foobar", "foobar");
    } catch (Throwable t) {
      if (t instanceof FuzzerSecurityIssueLow) {
        throw t;
      } else {
        // Unexpected exception, exit without producing a finding to let the test fail due to the
        // missing Java reproducer.
        // FIXME(fabian): This is hacky and will result in false positives as soon as we implement
        //  Java reproducers for fuzz target exits. Replace this with a more reliable signal.
        t.printStackTrace();
        System.exit(1);
      }
    }
  }
}
