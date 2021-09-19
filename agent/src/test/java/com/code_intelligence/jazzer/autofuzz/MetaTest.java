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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class MetaTest {
  private static FuzzedDataProvider makeFuzzedDataProvider(List<Object> replies) {
    try {
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
        try (ObjectOutputStream out = new ObjectOutputStream(bout)) {
          out.writeObject(new ArrayList<>(replies));
          String base64 = Base64.getEncoder().encodeToString(bout.toByteArray());
          return new CannedFuzzedDataProvider(base64);
        }
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public static boolean isFive(int arg) {
    return arg == 5;
  }

  @Test
  public void testConsume() {
    FuzzedDataProvider data = makeFuzzedDataProvider(Collections.singletonList(5));
    assertEquals(5, Meta.consume(data, int.class));
  }

  @Test
  public void testAutofuzz() {
    FuzzedDataProvider data = makeFuzzedDataProvider(Arrays.asList(5,
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
