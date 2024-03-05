/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Objects;

public class ObjectEqualsStringFuzzer {
  @FuzzTest
  void objectEqualsString(byte[] input) {
    String stringInput = new String(input);
    if (Objects.equals(stringInput, "ObjectsEqualsFuzzer")) {
      throw new FuzzerSecurityIssueLow("ObjectsEqualsFuzzer works!");
    }
  }
}
