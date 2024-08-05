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
import org.mockito.Mockito;

public class MockitoFuzzTest {
  public static class Foo {
    public String bar(String ignored) {
      return "bar";
    }
  }

  @FuzzTest
  void fuzzWithMockito(byte[] bytes) {
    // Mock the Foo class to trigger an instrumentation cycle,
    // if not properly ignored.
    Foo foo = Mockito.mock(Foo.class);
    foo.bar(new String(bytes));
  }
}
