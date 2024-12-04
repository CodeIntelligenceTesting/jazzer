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
