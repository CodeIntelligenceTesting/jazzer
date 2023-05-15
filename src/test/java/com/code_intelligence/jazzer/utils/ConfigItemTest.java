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
import static org.junit.Assume.assumeTrue;

import java.util.ArrayList;
import java.util.Collections;
import org.junit.Test;

public class ConfigItemTest {
  // TODO: reset system properties so multiple tests can run

  @Test
  public void intItemTest() {
    assertNull(System.getProperty("jazzer.foo"));

    ConfigItem.Int item = new ConfigItem.Int("jazzer", Collections.singletonList("foo"), 5);
    assertEquals(5, item.get().intValue());

    item.set(10);
    assertEquals(10, item.get().intValue());
  }

  @Test
  public void strItemTest() {
    assertNull(System.getProperty("jazzer.foo"));

    ConfigItem.Str item = new ConfigItem.Str("jazzer", Collections.singletonList("foo"), "bar");
    assertEquals("bar", item.get());

    item.set("baz");
    assertEquals("baz", item.get());
  }

  @Test
  public void loadFromEnvTest() {
    assumeTrue(System.getenv("JAZZER_FOO").equals("12345"));
    assertNull(System.getProperty("jazzer.foo"));

    Config.loadConfig(new ArrayList<>());
    // assertEquals("12345", Config.foo.get());
  }

  @Test
  public void loadFromEnvInvalidTest() {
    assumeTrue(System.getenv("JAZZER_BAR") != null);
    assertEquals("bar", System.getenv("JAZZER_BAR"));
    assertNull(System.getProperty("jazzer.bar"));

    assertThrows(NumberFormatException.class, () -> { Config.loadConfig(new ArrayList<>()); });
  }
}
