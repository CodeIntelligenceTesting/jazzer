/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
