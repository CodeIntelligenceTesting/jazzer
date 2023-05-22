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

import java.util.ArrayList;
import java.util.Arrays;
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
  public void strListTest() {
    assertNull(System.getProperty("jazzer.foo"));

    ConfigItem.StrList item =
        new ConfigItem.StrList("jazzer", Collections.singletonList("foo"), ',');
    assertFalse(item.isSet());
    assertTrue(item.get().isEmpty());

    item.set(Arrays.asList("bar", "baz"));
    assertEquals(Arrays.asList("bar", "baz"), item.get());
  }
}
