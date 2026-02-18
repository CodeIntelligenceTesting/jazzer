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

package com.code_intelligence.jazzer.runtime;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import org.junit.Test;

public class TraceCmpHooksTest {
  private static final ExecutorService ES = Executors.newFixedThreadPool(5);

  @Test
  public void cmpHookShouldHandleConcurrentModifications() throws InterruptedException {
    String arg = "test";
    Map<String, Object> map = new HashMap<>();
    map.put(arg, arg);

    // Add elements to map asynchronously
    Function<Integer, Runnable> put =
        (final Integer num) ->
            () -> {
              map.put(String.valueOf(num), num);
            };
    for (int i = 0; i < 1_000_000; i++) {
      ES.submit(put.apply(i));
    }

    // Call hook
    for (int i = 0; i < 1_000; i++) {
      TraceCmpHooks.mapGet(null, map, new Object[] {arg}, 1, null);
    }

    ES.shutdown();
    // noinspection ResultOfMethodCallIgnored
    ES.awaitTermination(5, TimeUnit.SECONDS);
  }

  @Test
  public void handlesNullValuesInArrayCompare() {
    byte[] b1 = new byte[10];
    byte[] b2 = null;
    // Make sure we don't crash the JVM on null arrays.
    TraceCmpHooks.arraysEquals(null, null, new Object[] {b1, b2}, 1, false);
    TraceCmpHooks.arraysCompare(null, null, new Object[] {b1, b2}, 1, 1);
  }

  @Test
  public void traceCmpDoubleWrapperShouldMatchDcmpSemantics() {
    assertEquals(0, invokeTraceCmpDoubleWrapper(-0.0d, +0.0d, /* nanResult= */ -1));
    assertEquals(0, invokeTraceCmpDoubleWrapper(+0.0d, -0.0d, /* nanResult= */ 1));
    assertEquals(-1, invokeTraceCmpDoubleWrapper(Double.NaN, 1.0d, /* nanResult= */ -1));
    assertEquals(1, invokeTraceCmpDoubleWrapper(Double.NaN, 1.0d, /* nanResult= */ 1));
  }

  @Test
  public void traceCmpFloatWrapperShouldMatchFcmpSemantics() {
    assertEquals(0, invokeTraceCmpFloatWrapper(-0.0f, +0.0f, /* nanResult= */ -1));
    assertEquals(0, invokeTraceCmpFloatWrapper(+0.0f, -0.0f, /* nanResult= */ 1));
    assertEquals(-1, invokeTraceCmpFloatWrapper(Float.NaN, 1.0f, /* nanResult= */ -1));
    assertEquals(1, invokeTraceCmpFloatWrapper(Float.NaN, 1.0f, /* nanResult= */ 1));
  }

  private static int invokeTraceCmpDoubleWrapper(double arg1, double arg2, int nanResult) {
    try {
      Class<?> callbacksClass =
          Class.forName("com.code_intelligence.jazzer.runtime.TraceDataFlowNativeCallbacks");
      return (int)
          callbacksClass
              .getMethod("traceCmpDoubleWrapper", double.class, double.class, int.class, int.class)
              .invoke(null, arg1, arg2, nanResult, 1);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static int invokeTraceCmpFloatWrapper(float arg1, float arg2, int nanResult) {
    try {
      Class<?> callbacksClass =
          Class.forName("com.code_intelligence.jazzer.runtime.TraceDataFlowNativeCallbacks");
      return (int)
          callbacksClass
              .getMethod("traceCmpFloatWrapper", float.class, float.class, int.class, int.class)
              .invoke(null, arg1, arg2, nanResult, 1);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }
}
