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

import java.nio.ByteBuffer;

public final class DirectByteBufferCoverageMap {
  // The current target, JsonSanitizer, uses less than 2048 coverage counters.
  private static final int NUM_COUNTERS = 4096;
  public static final ByteBuffer counters = ByteBuffer.allocateDirect(NUM_COUNTERS);

  public static void enlargeIfNeeded(int nextId) {
    // Statically sized counters buffer.
  }

  public static void recordCoverage(final int id) {
    final byte counter = counters.get(id);
    if (counter == -1) {
      counters.put(id, (byte) 1);
    } else {
      counters.put(id, (byte) (counter + 1));
    }
  }
}
