/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.autofuzz;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.List;

class TestHelpers {
  static void assertGeneralEquals(Object expected, Object actual) {
    Class<?> type = expected != null ? expected.getClass() : Object.class;
    if (type.isArray()) {
      if (type.getComponentType() == boolean.class) {
        assertArrayEquals((boolean[]) expected, (boolean[]) actual);
      } else if (type.getComponentType() == char.class) {
        assertArrayEquals((char[]) expected, (char[]) actual);
      } else if (type.getComponentType() == short.class) {
        assertArrayEquals((short[]) expected, (short[]) actual);
      } else if (type.getComponentType() == long.class) {
        assertArrayEquals((long[]) expected, (long[]) actual);
      } else {
        assertArrayEquals((Object[]) expected, (Object[]) actual);
      }
    } else if (type == ByteArrayInputStream.class) {
      ByteArrayInputStream expectedStream = (ByteArrayInputStream) expected;
      ByteArrayInputStream actualStream = (ByteArrayInputStream) actual;
      assertArrayEquals(readAllBytes(expectedStream), readAllBytes(actualStream));
    } else {
      assertEquals(expected, actual);
    }
  }

  static void consumeTestCase(
      Object expectedResult, String expectedResultString, List<Object> cannedData) {
    Class<?> type = expectedResult != null ? expectedResult.getClass() : Object.class;
    consumeTestCase(type, expectedResult, expectedResultString, cannedData);
  }

  static void consumeTestCase(
      Type type, Object expectedResult, String expectedResultString, List<Object> cannedData) {
    AutofuzzCodegenVisitor visitor = new AutofuzzCodegenVisitor();
    FuzzedDataProvider data = CannedFuzzedDataProvider.create(cannedData);
    assertGeneralEquals(expectedResult, new Meta(null).consume(data, type, visitor));
    assertEquals(expectedResultString, visitor.generate());
  }

  static void autofuzzTestCase(
      Object expectedResult,
      String expectedResultString,
      Executable func,
      List<Object> cannedData) {
    AutofuzzCodegenVisitor visitor = new AutofuzzCodegenVisitor();
    FuzzedDataProvider data = CannedFuzzedDataProvider.create(cannedData);
    if (func instanceof Method) {
      assertGeneralEquals(expectedResult, new Meta(null).autofuzz(data, (Method) func, visitor));
    } else {
      assertGeneralEquals(
          expectedResult, new Meta(null).autofuzz(data, (Constructor<?>) func, visitor));
    }
    assertEquals(expectedResultString, visitor.generate());
  }

  private static byte[] readAllBytes(ByteArrayInputStream in) {
    byte[] result = new byte[in.available()];
    in.read(result, 0, in.available());
    return result;
  }
}
