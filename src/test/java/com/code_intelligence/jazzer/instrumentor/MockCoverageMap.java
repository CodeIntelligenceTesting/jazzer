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
import java.util.ArrayList;
import java.util.Arrays;

public class MockCoverageMap {
  public static final int SIZE = 65536;
  public static final ByteBuffer counters = ByteBuffer.allocate(SIZE);

  private static final ByteBuffer previous_mem = ByteBuffer.allocate(SIZE);
  public static ArrayList<Integer> locations = new ArrayList<>();

  public static void updated() {
    int updated_pos = -1;
    for (int i = 0; i < SIZE; i++) {
      if (previous_mem.get(i) != counters.get(i)) {
        updated_pos = i;
      }
    }
    locations.add(updated_pos);
    System.arraycopy(counters.array(), 0, previous_mem.array(), 0, SIZE);
  }

  public static void enlargeIfNeeded(int nextId) {
    // This mock coverage map is statically sized.
  }

  public static void recordCoverage(int id) {
    byte counter = counters.get(id);
    counters.put(id, (byte) (counter == -1 ? 1 : counter + 1));
  }

  public static void clear() {
    Arrays.fill(counters.array(), (byte) 0);
    Arrays.fill(previous_mem.array(), (byte) 0);
    locations.clear();
  }
}
