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
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

class MutatorFuzzTest {
  @FuzzTest(maxExecutions = 10000)
  void mutatorFuzz(@NotNull String s) {
    if (s.length() > 0) {
        byte sAt0 = (byte) s.charAt(0);
        if (sAt0 == (byte) 0xFF) {
          throw new AssertionError("Found expected JUnit mutator test issue");
        }
      }

/*     for (int i = 0; i < s.length(); i++) {
      
      
    } */
    /* System.err.println("Fuzzing with input: " + s.length() + ", str: " + s);
    // Check that the mutator is actually doing something.
    if (s.equals("Hello, world!")) {
      System.err.println("HERE-----------------------------------------------------");
      throw new AssertionError("Found expected JUnit mutator test issue");
    }
  } */
  }
}
