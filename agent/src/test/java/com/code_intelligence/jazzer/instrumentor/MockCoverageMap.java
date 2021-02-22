// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.instrumentor;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

public class MockCoverageMap {
  public static final int SIZE = 65536;
  public static final ByteBuffer mem = ByteBuffer.allocate(SIZE);
  public static int prev_location = 0; // is used in byte code directly

  private static final ByteBuffer previous_mem = ByteBuffer.allocate(SIZE);
  public static ArrayList<Integer> locations = new ArrayList<>();

  public static void updated() {
    int updated_pos = -1;
    for (int i = 0; i < SIZE; i++) {
      if (previous_mem.get(i) != mem.get(i)) {
        updated_pos = i;
      }
    }
    locations.add(updated_pos);
    System.arraycopy(mem.array(), 0, previous_mem.array(), 0, SIZE);
  }

  public static void clear() {
    Arrays.fill(mem.array(), (byte) 0);
    Arrays.fill(previous_mem.array(), (byte) 0);
    locations.clear();
  }
}
