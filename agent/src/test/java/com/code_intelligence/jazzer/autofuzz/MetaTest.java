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

import static com.code_intelligence.jazzer.autofuzz.TestHelpers.autofuzzTestCase;
import static com.code_intelligence.jazzer.autofuzz.TestHelpers.consumeTestCase;
import static org.junit.Assert.assertEquals;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.json.JsonSanitizer;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;

public class MetaTest {
  public static boolean isFive(int arg) {
    return arg == 5;
  }

  public static boolean intEquals(int arg1, int arg2) {
    return arg1 == arg2;
  }

  public enum TestEnum {
    FOO,
    BAR,
    BAZ,
  }

  @Test
  public void testConsume() {
    consumeTestCase(5, "5", Collections.singletonList(5));
    consumeTestCase((short) 5, "(short) 5", Collections.singletonList((short) 5));
    consumeTestCase(5L, "5L", Collections.singletonList(5L));
    consumeTestCase(5.0F, "5.0F", Collections.singletonList(5.0F));
    consumeTestCase('\n', "'\\\\n'", Collections.singletonList('\n'));
    consumeTestCase('\'', "'\\\\''", Collections.singletonList('\''));
    consumeTestCase('\\', "'\\\\'", Collections.singletonList('\\'));

    String testString = "foo\n\t\\\"bar";
    // The expected string is obtained from testString by escaping, wrapping into quotes and
    // escaping again.
    consumeTestCase(testString, "\"foo\\\\n\\\\t\\\\\\\\\"bar\"",
        Arrays.asList((byte) 1, // do not return null
            testString.length(), testString));

    consumeTestCase(null, "null", Collections.singletonList((byte) 0));

    boolean[] testBooleans = new boolean[] {true, false, true};
    consumeTestCase(testBooleans, "new boolean[]{true, false, true}",
        Arrays.asList((byte) 1, // do not return null for the array
            2 * 3, testBooleans));

    char[] testChars = new char[] {'a', '\n', '\''};
    consumeTestCase(testChars, "new char[]{'a', '\\\\n', '\\\\''}",
        Arrays.asList((byte) 1, // do not return null for the array
            2 * 3 * Character.BYTES + Character.BYTES, testChars[0], 2 * 3 * Character.BYTES,
            2 * 3 * Character.BYTES, // remaining bytes, 2 times what is needed for 3 chars
            testChars[1], testChars[2]));

    char[] testNoChars = new char[] {};
    consumeTestCase(testNoChars, "new char[]{}",
        Arrays.asList((byte) 1, // do not return null for the array
            0, 'a', 0, 0));

    short[] testShorts = new short[] {(short) 1, (short) 2, (short) 3};
    consumeTestCase(testShorts, "new short[]{(short) 1, (short) 2, (short) 3}",
        Arrays.asList((byte) 1, // do not return null for the array
            2 * 3 * Short.BYTES, // remaining bytes
            testShorts));

    long[] testLongs = new long[] {1L, 2L, 3L};
    consumeTestCase(testLongs, "new long[]{1L, 2L, 3L}",
        Arrays.asList((byte) 1, // do not return null for the array
            2 * 3 * Long.BYTES, // remaining bytes
            testLongs));

    consumeTestCase(new String[] {"foo", "bar", "foo\nbar"},
        "new java.lang.String[]{\"foo\", \"bar\", \"foo\\\\nbar\"}",
        Arrays.asList((byte) 1, // do not return null for the array
            32, // remaining bytes
            (byte) 1, // do not return null for the string
            31, // remaining bytes
            "foo",
            28, // remaining bytes
            28, // array length
            (byte) 1, // do not return null for the string
            27, // remaining bytes
            "bar",
            (byte) 1, // do not return null for the string
            23, // remaining bytes
            "foo\nbar"));

    byte[] testInputStreamBytes = new byte[] {(byte) 1, (byte) 2, (byte) 3};
    consumeTestCase(new ByteArrayInputStream(testInputStreamBytes),
        "new java.io.ByteArrayInputStream(new byte[]{(byte) 1, (byte) 2, (byte) 3})",
        Arrays.asList((byte) 1, // do not return null for the InputStream
            2 * 3, // remaining bytes (twice the desired length)
            testInputStreamBytes));

    consumeTestCase(TestEnum.BAR,
        String.format("%s.%s", TestEnum.class.getName(), TestEnum.BAR.name()),
        Arrays.asList((byte) 1, // do not return null for the enum value
            1 /* second value */
            ));

    consumeTestCase(YourAverageJavaClass.class,
        "com.code_intelligence.jazzer.autofuzz.YourAverageJavaClass.class",
        Collections.singletonList((byte) 1));
  }

  @Test
  public void testAutofuzz() throws NoSuchMethodException {
    autofuzzTestCase(true, "com.code_intelligence.jazzer.autofuzz.MetaTest.isFive(5)",
        MetaTest.class.getMethod("isFive", int.class), Collections.singletonList(5));
    autofuzzTestCase(false, "com.code_intelligence.jazzer.autofuzz.MetaTest.intEquals(5, 4)",
        MetaTest.class.getMethod("intEquals", int.class, int.class), Arrays.asList(5, 4));
    autofuzzTestCase("foobar", "\"foo\".concat(\"bar\")",
        String.class.getMethod("concat", String.class),
        Arrays.asList((byte) 1, 6, "foo", (byte) 1, 6, "bar"));
    autofuzzTestCase("jazzer", "new java.lang.String(\"jazzer\")",
        String.class.getConstructor(String.class), Arrays.asList((byte) 1, 12, "jazzer"));
    autofuzzTestCase("\"jazzer\"", "com.google.json.JsonSanitizer.sanitize(\"jazzer\")",
        JsonSanitizer.class.getMethod("sanitize", String.class),
        Arrays.asList((byte) 1, 12, "jazzer"));

    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(Arrays.asList((byte) 1, // do not return null
            8, // remainingBytes
            "buzz"));
    assertEquals("fizzbuzz", Meta.autofuzz(data, "fizz" ::concat));
  }
}
