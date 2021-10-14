// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.autofuzz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.json.JsonSanitizer;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

public class MetaTest {
  public static boolean isFive(int arg) {
    return arg == 5;
  }

  @Test
  public void testConsume() {
    FuzzedDataProvider data = CannedFuzzedDataProvider.create(Collections.singletonList(5));
    assertEquals(5, Meta.consume(data, int.class));
  }

  @Test
  public void testAutofuzz() {
    FuzzedDataProvider data = CannedFuzzedDataProvider.create(Arrays.asList(5,
        6, // remainingBytes
        "foo",
        6, // remainingBytes
        "bar",
        8, // remainingBytes
        "buzz",
        6, // remainingBytes
        "jazzer",
        6, // remainingBytes
        "jazzer"));
    assertTrue(Meta.autofuzz(data, MetaTest::isFive));
    assertEquals("foobar", Meta.autofuzz(data, String::concat));
    assertEquals("fizzbuzz", Meta.autofuzz(data, "fizz" ::concat));
    assertEquals("jazzer", Meta.autofuzz(data, (Function1<String, ?>) String::new));
    assertEquals(
        "\"jazzer\"", Meta.autofuzz(data, (Function1<String, String>) JsonSanitizer::sanitize));
  }
}
