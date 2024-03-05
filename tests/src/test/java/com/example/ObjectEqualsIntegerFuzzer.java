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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Objects;

public class ObjectEqualsIntegerFuzzer {
  @FuzzTest
  void objectEqualsInteger(FuzzedDataProvider fdp) {
    int integer = fdp.consumeInt();
    if (Objects.equals(integer, 4711)) {
      throw new FuzzerSecurityIssueLow("ObjectsEqualsFuzzer works!");
    }
  }
}
