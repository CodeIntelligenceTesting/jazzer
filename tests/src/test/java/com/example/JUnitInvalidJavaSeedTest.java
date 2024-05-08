/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JUnitInvalidJavaSeedTest {

  static class ConstructorBased {
    final int b;

    ConstructorBased(int a) {
      this.b = a * a;
    }
  }

  public static Stream<Arguments> seeds() {
    return Stream.of(arguments(new ConstructorBased(42)));
  }

  @MethodSource("seeds")
  @FuzzTest(maxExecutions = 10)
  void fuzzTest(ConstructorBased ignored) {}
}
