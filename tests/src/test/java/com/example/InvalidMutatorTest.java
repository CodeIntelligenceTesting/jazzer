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
import com.code_intelligence.jazzer.mutation.annotation.UrlSegment;

public class InvalidMutatorTest {

  @FuzzTest
  public void invalidParameter(System ignored) {
    throw new IllegalStateException("This method should not be executed");
  }

  @FuzzTest
  public void invalidAnnotation(@UrlSegment Integer ignored) {
    throw new IllegalStateException("This method should not be executed");
  }
}
