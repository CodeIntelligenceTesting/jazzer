/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.mutation.mutator.torc;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

/**
 * Table of recent comparisons (Torc) mutator using the Torc library. Uses ring buffer to store
 * recent comparisons.
 */
public class Torc {
  // ring buffer containing recent comparisons
  private static final int SIZE = 128;
  private static List<Pair> torc = new ArrayList<>(SIZE);
  private static int index = 0;
  private static int count = 0;

  private Torc() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  public static void add(byte[] data1, byte[] data2) {
    if (data1 == null || data1.length == 0 || data2 == null || data2.length == 0) {
      return;
    }
    System.err.println("[TORC] Adding comparison: " + Arrays.toString(data1) + " vs " + Arrays.toString(data2));
    Pair p = new Pair(data1, data2);
    if (torc.size() < SIZE) {
      torc.add(p);
    } else {
      torc.set(index, p);
      index = (index + 1) % SIZE;
    }
  }

  public static Pair get(PseudoRandom prng) {
    int index = prng.indexIn(torc.size());
    System.err.println("Torc returning index " + index);
    return torc.get(index);
  }

  public static class Pair {
    public final byte[] operand1;
    public final byte[] operand2;

    Pair(byte[] a, byte[] b) {
      this.operand1 = a;
      this.operand2 = b;
    }
  }
}
