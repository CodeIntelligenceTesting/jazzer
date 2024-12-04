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

package com.code_intelligence.jazzer.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;

public class AutofuzzTest {
  public interface UnimplementedInterface {}

  public interface ImplementedInterface {}

  public static class ImplementingClass implements ImplementedInterface {}

  private static boolean implIsNotNull(ImplementedInterface impl) {
    return impl != null;
  }

  private static boolean implIsNotNull(UnimplementedInterface impl) {
    return impl != null;
  }

  private static void checkAllTheArguments(
      String arg1, int arg2, byte arg3, ImplementedInterface arg4) {
    if (!arg1.equals("foobar") || arg2 != 42 || arg3 != 5 || arg4 == null) {
      throw new IllegalArgumentException();
    }
  }

  @Test
  public void testConsume() {
    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(
            Arrays.asList(
                (byte) 1 /* do not return null */,
                0 /* first class on the classpath */,
                (byte) 1 /* do not return null */,
                0 /* first constructor */));
    ImplementedInterface result = Autofuzz.consume(data, ImplementedInterface.class);
    assertNotNull(result);
  }

  @Test
  public void testConsumeFailsWithoutException() {
    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(
            Collections.singletonList(
                (byte) 1 /* do not return null without searching for implementing classes */));
    assertNull(Autofuzz.consume(data, UnimplementedInterface.class));
  }

  @Test
  public void testAutofuzz() {
    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(
            Arrays.asList(
                (byte) 1 /* do not return null */,
                0 /* first class on the classpath */,
                (byte) 1 /* do not return null */,
                0 /* first constructor */));
    assertEquals(
        Boolean.TRUE,
        Autofuzz.autofuzz(data, (Function1<ImplementedInterface, ?>) AutofuzzTest::implIsNotNull));
  }

  @Test
  public void testAutofuzzFailsWithException() {
    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(
            Collections.singletonList((byte) 1 /* do not return null */));
    try {
      Autofuzz.autofuzz(data, (Function1<UnimplementedInterface, ?>) AutofuzzTest::implIsNotNull);
    } catch (AutofuzzConstructionException e) {
      // Pass.
      return;
    }
    fail("should have thrown an AutofuzzConstructionException");
  }

  @Test
  public void testAutofuzzConsumer() {
    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(
            Arrays.asList(
                (byte) 1 /* do not return null */,
                6 /* string length */,
                "foobar",
                42,
                (byte) 5,
                (byte) 1 /* do not return null */,
                0 /* first class on the classpath */,
                (byte) 1 /* do not return null */,
                0 /* first constructor */));
    Autofuzz.autofuzz(data, AutofuzzTest::checkAllTheArguments);
  }

  @Test
  public void testAutofuzzConsumerThrowsException() {
    FuzzedDataProvider data =
        CannedFuzzedDataProvider.create(
            Arrays.asList(
                (byte) 1 /* do not return null */,
                6 /* string length */,
                "foobar",
                42,
                (byte) 5,
                (byte) 0 /* *do* return null */));
    try {
      Autofuzz.autofuzz(data, AutofuzzTest::checkAllTheArguments);
    } catch (IllegalArgumentException e) {
      // Pass.
      return;
    }
    fail("should have thrown an IllegalArgumentException");
  }
}
