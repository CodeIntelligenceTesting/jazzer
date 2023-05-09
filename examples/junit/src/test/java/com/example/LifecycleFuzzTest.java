/*
 * Copyright 2022 Code Intelligence GmbH
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

package com.example;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;

@TestMethodOrder(MethodOrderer.MethodName.class)
@ExtendWith(LifecycleFuzzTest.LifecycleInstancePostProcessor.class)
class LifecycleFuzzTest {
  // In fuzzing mode, the test is invoked once on the empty input and once with Jazzer.
  private static final int EXPECTED_EACH_COUNT =
      System.getenv().getOrDefault("JAZZER_FUZZ", "").isEmpty() ? 1 : 2;

  private static int beforeAllCount = 0;
  private static int beforeEachGlobalCount = 0;
  private static int afterEachGlobalCount = 0;
  private static int afterAllCount = 0;

  private boolean beforeEachCalledOnInstance = false;
  private boolean testInstancePostProcessorCalledOnInstance = false;

  @BeforeAll
  static void beforeAll() {
    beforeAllCount++;
  }

  @BeforeEach
  void beforeEach() {
    beforeEachGlobalCount++;
    beforeEachCalledOnInstance = true;
  }

  @Disabled
  @FuzzTest
  void disabledFuzz(byte[] data) {
    throw new AssertionError("This test should not be executed");
  }

  @FuzzTest(maxDuration = "1s")
  void lifecycleFuzz(byte[] data) {
    Assertions.assertEquals(1, beforeAllCount);
    Assertions.assertEquals(beforeEachGlobalCount, afterEachGlobalCount + 1);
    Assertions.assertTrue(beforeEachCalledOnInstance);
    Assertions.assertTrue(testInstancePostProcessorCalledOnInstance);
  }

  @AfterEach
  void afterEach() {
    afterEachGlobalCount++;
  }

  @AfterAll
  static void afterAll() throws IOException {
    afterAllCount++;
    Assertions.assertEquals(1, beforeAllCount);
    Assertions.assertEquals(EXPECTED_EACH_COUNT, beforeEachGlobalCount);
    Assertions.assertEquals(EXPECTED_EACH_COUNT, afterEachGlobalCount);
    Assertions.assertEquals(1, afterAllCount);
    throw new IOException();
  }

  static class LifecycleInstancePostProcessor implements TestInstancePostProcessor {
    @Override
    public void postProcessTestInstance(Object o, ExtensionContext extensionContext) {
      ((LifecycleFuzzTest) o).testInstancePostProcessorCalledOnInstance = true;
    }
  }
}
