/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
