/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
