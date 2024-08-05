/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TestMethodInManifestFuzzer {
  @Order(0)
  @FuzzTest
  void notThisFuzzTest(byte[] bytes) {}

  @Order(1)
  @FuzzTest
  void thisFuzzTest(byte[] bytes) {
    throw new FuzzerSecurityIssueCritical();
  }

  @Order(2)
  @FuzzTest
  void alsoNotThisFuzzTest(byte[] bytes) {}
}
