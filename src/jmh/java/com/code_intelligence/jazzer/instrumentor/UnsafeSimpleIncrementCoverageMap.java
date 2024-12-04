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

package com.code_intelligence.jazzer.instrumentor;

import java.lang.reflect.Field;
import sun.misc.Unsafe;

public final class UnsafeSimpleIncrementCoverageMap {
  private static final Unsafe UNSAFE;

  static {
    Unsafe unsafe;
    try {
      Field f = Unsafe.class.getDeclaredField("theUnsafe");
      f.setAccessible(true);
      unsafe = (Unsafe) f.get(null);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      e.printStackTrace();
      System.exit(1);
      // Not reached.
      unsafe = null;
    }
    UNSAFE = unsafe;
  }

  // The current target, JsonSanitizer, uses less than 2048 coverage counters.
  private static final long NUM_COUNTERS = 4096;
  private static final long countersAddress = UNSAFE.allocateMemory(NUM_COUNTERS);

  static {
    UNSAFE.setMemory(countersAddress, NUM_COUNTERS, (byte) 0);
  }

  public static void enlargeIfNeeded(int nextId) {
    // Statically sized counters buffer.
  }

  public static void recordCoverage(final int id) {
    final long address = countersAddress + id;
    UNSAFE.putByte(address, (byte) (UNSAFE.getByte(address) + 1));
  }
}
