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

package com.code_intelligence.jazzer.driver;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.junit.Test;

public class OptTest {
  @Test
  public void splitString() {
    assertStringSplit("", ',');
    assertStringSplit(",,,,,", ',');
    assertStringSplit("fir\\\\st se\\ cond      third", ' ', "fir\\st", "se cond", "third");
    assertStringSplit("first ", ' ', "first");
    assertStringSplit("first\\", ' ', "first");
  }

  @Test(expected = IllegalArgumentException.class)
  public void splitString_noBackslashAsSeparator() {
    assertStringSplit("foo", '\\');
  }

  public void assertStringSplit(String str, char sep, String... tokens) {
    assertEquals(Arrays.stream(tokens).collect(Collectors.toList()),
        Opt.splitOnUnescapedSeparator(str, sep));
  }
}
