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

@TestMethodOrder(MethodOrderer.MethodName.class)
class LifecycleFuzzTest {
  private static int beforeAllCount = 0;
  private static int beforeEachCount = 0;
  private static int afterEachCount = 0;
  private static int afterAllCount = 0;

  @BeforeAll
  static void beforeAll() {
    beforeAllCount++;
  }

  @BeforeEach
  void beforeEach() {
    beforeEachCount++;
  }

  @Disabled
  @FuzzTest
  void disabledFuzz(byte[] data) {
    throw new AssertionError("This test should not be executed");
  }

  @FuzzTest(maxDuration = "1s")
  void lifecycleFuzz(byte[] data) {
    Assertions.assertEquals(1, beforeAllCount);
    Assertions.assertEquals(1, beforeEachCount);
    Assertions.assertEquals(0, afterEachCount);
  }

  @AfterEach
  void afterEach() {
    afterEachCount++;
  }

  @AfterAll
  static void afterAll() throws IOException {
    afterAllCount++;
    Assertions.assertEquals(1, beforeAllCount);
    Assertions.assertEquals(1, beforeEachCount);
    Assertions.assertEquals(1, afterEachCount);
    Assertions.assertEquals(1, afterAllCount);
    throw new IOException();
  }
}
