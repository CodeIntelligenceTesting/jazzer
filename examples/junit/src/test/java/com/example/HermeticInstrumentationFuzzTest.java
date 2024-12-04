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
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@SuppressWarnings("InvalidPatternSyntax")
@Execution(ExecutionMode.CONCURRENT)
class HermeticInstrumentationFuzzTest {
  class VulnerableFuzzClass {
    public void vulnerableMethod(String input) {
      Pattern.compile(input);
    }
  }

  class VulnerableUnitClass {
    public void vulnerableMethod(String input) {
      Pattern.compile(input);
    }
  }

  @FuzzTest
  @Execution(ExecutionMode.CONCURRENT)
  void fuzzTest1(byte[] data) {
    new VulnerableFuzzClass().vulnerableMethod("[");
  }

  @Test
  @Execution(ExecutionMode.CONCURRENT)
  void unitTest1() {
    new VulnerableUnitClass().vulnerableMethod("[");
  }

  @FuzzTest
  @Execution(ExecutionMode.CONCURRENT)
  void fuzzTest2(byte[] data) {
    Pattern.compile("[");
  }

  @Test
  @Execution(ExecutionMode.CONCURRENT)
  void unitTest2() {
    Pattern.compile("[");
  }
}
