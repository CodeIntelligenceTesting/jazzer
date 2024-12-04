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
