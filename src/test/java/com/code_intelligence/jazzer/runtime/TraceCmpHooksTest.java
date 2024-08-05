/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

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
}
