/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.function.Supplier;

class JUnitAgentConfigurationFuzzTest {
  @FuzzTest
  void testConfiguration(byte[] bytes) {
    assertEquals(singletonList("com.example.**"), getLazyOptValue("instrumentationIncludes"));
    assertEquals(singletonList("com.example.**"), getLazyOptValue("customHookIncludes"));
  }

  private static Object getLazyOptValue(String name) {
    try {
      Supplier<Object> supplier =
          (Supplier<Object>)
              Class.forName("com.code_intelligence.jazzer.driver.Opt").getField(name).get(null);
      return supplier.get();
    } catch (NoSuchFieldException | ClassNotFoundException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }
}
