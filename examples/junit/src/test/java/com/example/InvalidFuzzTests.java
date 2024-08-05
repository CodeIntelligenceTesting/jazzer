/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.TestInfo;

class InvalidFuzzTests {
  @FuzzTest
  void invalidParameterCountFuzz() {}

  @FuzzTest
  void parameterResolverFuzz(FuzzedDataProvider data, TestInfo testInfo) {
    throw new RuntimeException(testInfo.getDisplayName());
  }
}
