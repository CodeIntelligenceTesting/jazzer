/*
 * Copyright 2026 Code Intelligence GmbH
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

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

/**
 * Same as {@link FfmCoverageMap}, but only accesses the FFM API (JDK 22+) via method handles. This
 * class therefore compiles with Java 8 source level and could ship in the same jar as the
 * Unsafe-backed coverage map, as long as it is only loaded on JDK 22+.
 */
public final class FfmMethodHandleCoverageMap {
  // The current target, JsonSanitizer, uses less than 2048 coverage counters.
  private static final long NUM_COUNTERS = 4096;

  // MemorySegment#get(ValueLayout.OfByte, long) with the segment and layout bound: (long)byte
  private static final MethodHandle GET_BYTE;
  // MemorySegment#set(ValueLayout.OfByte, long, byte) with the segment and layout bound:
  // (long,byte)void
  private static final MethodHandle SET_BYTE;

  static {
    try {
      Class<?> arena = Class.forName("java.lang.foreign.Arena");
      Class<?> memorySegment = Class.forName("java.lang.foreign.MemorySegment");
      Class<?> ofByte = Class.forName("java.lang.foreign.ValueLayout$OfByte");
      MethodHandles.Lookup lookup = MethodHandles.publicLookup();

      Object javaByte =
          Class.forName("java.lang.foreign.ValueLayout").getField("JAVA_BYTE").get(null);
      Object globalArena =
          lookup.findStatic(arena, "global", MethodType.methodType(arena)).invoke();
      // Zero-initialized native memory that is never freed. Its address() could be handed to
      // libFuzzer just like the address of the Unsafe-backed map.
      Object counters =
          lookup
              .findVirtual(arena, "allocate", MethodType.methodType(memorySegment, long.class))
              .invoke(globalArena, NUM_COUNTERS);

      GET_BYTE =
          MethodHandles.insertArguments(
              lookup.findVirtual(
                  memorySegment, "get", MethodType.methodType(byte.class, ofByte, long.class)),
              0,
              counters,
              javaByte);
      SET_BYTE =
          MethodHandles.insertArguments(
              lookup.findVirtual(
                  memorySegment,
                  "set",
                  MethodType.methodType(void.class, ofByte, long.class, byte.class)),
              0,
              counters,
              javaByte);
    } catch (Throwable t) {
      throw new ExceptionInInitializerError(t);
    }
  }

  public static void enlargeIfNeeded(int nextId) {
    // Statically sized counters buffer.
  }

  public static void recordCoverage(final int id) {
    try {
      final byte counter = (byte) GET_BYTE.invokeExact((long) id);
      SET_BYTE.invokeExact((long) id, (byte) (counter == -1 ? 1 : counter + 1));
    } catch (Throwable t) {
      throw new IllegalStateException("Failed to record coverage", t);
    }
  }
}
