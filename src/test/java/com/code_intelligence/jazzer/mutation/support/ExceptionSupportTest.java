/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.ExceptionSupport.asUnchecked;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ExceptionSupportTest {
  @Test
  void testAsUnchecked_withUncheckedException() {
    assertThrows(
        IllegalStateException.class,
        () -> {
          // noinspection TrivialFunctionalExpressionUsage
          ((Runnable)
                  () -> {
                    throw asUnchecked(new IllegalStateException());
                  })
              .run();
        });
  }

  @Test
  void testAsUnchecked_withCheckedException() {
    assertThrows(
        IOException.class,
        () -> {
          // Verify that asUnchecked can be used to throw a checked exception in a function that
          // doesn't
          // declare it as being thrown.
          // noinspection TrivialFunctionalExpressionUsage
          ((Runnable)
                  () -> {
                    throw asUnchecked(new IOException());
                  })
              .run();
        });
  }
}
