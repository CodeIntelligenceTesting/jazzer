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
