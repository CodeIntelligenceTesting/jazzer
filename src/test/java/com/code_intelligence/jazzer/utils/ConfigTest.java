/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.utils;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

import org.junit.Test;

public class ConfigTest {
  @Test
  public void loadFromEnvTest() {
    assumeEnvEquals("JAZZER_KEEP_GOING", "10");

    Config.loadConfig(new ArrayList<>());
    assertEquals(0, Long.compareUnsigned(10L, Config.keepGoing.get()));
  }

  @Test
  public void loadFromEnvInvalidTest() {
    assumeEnvEquals("JAZZER_KEEP_GOING", "foo");
    assertThrows(NumberFormatException.class, () -> Config.loadConfig(new ArrayList<>()));
  }

  @Test
  public void loadFromManifestTest() {

  }

  @Test
  public void loadFromCliTest() {
    Config.loadConfig(Collections.singletonList("--keep_going=15"));
    assertEquals(0, Long.compareUnsigned(15L, Config.keepGoing.get()));
  }

  private static void assumeEnvEquals(String key, String value) {
    assumeNotNull(System.getenv(key));
    assumeTrue(System.getenv(key).equals(value));
  }
}
