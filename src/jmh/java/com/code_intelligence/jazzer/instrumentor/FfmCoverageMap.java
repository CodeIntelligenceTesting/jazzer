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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/** A coverage map backed by the Foreign Function & Memory API (JDK 22+). */
public final class FfmCoverageMap {
  // The current target, JsonSanitizer, uses less than 2048 coverage counters.
  private static final long NUM_COUNTERS = 4096;

  // Zero-initialized native memory that is never freed. Its address() could be handed to libFuzzer
  // just like the address of the Unsafe-backed map.
  private static final MemorySegment counters = Arena.global().allocate(NUM_COUNTERS);

  public static void enlargeIfNeeded(int nextId) {
    // Statically sized counters buffer.
  }

  public static void recordCoverage(final int id) {
    final byte counter = counters.get(ValueLayout.JAVA_BYTE, id);
    counters.set(ValueLayout.JAVA_BYTE, id, (byte) (counter == -1 ? 1 : counter + 1));
  }
}
