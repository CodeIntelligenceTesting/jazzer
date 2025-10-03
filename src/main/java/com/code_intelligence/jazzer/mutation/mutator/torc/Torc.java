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

/**
 * Table of recent comparisons (Torc) mutator using the Torc library. Uses ring buffer to store
 * recent comparisons.
 */
public class Torc {
  // ring buffer
  private static final int SIZE = 1024;
  private static final byte[][] buffer = new byte[SIZE][];
  private static int index = 0;

  private Torc() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  public static void add(byte[] data) {
    buffer[index++ % SIZE] = data;
  }

  public static byte[] get(PseudoRandom prng) {
    return prng.pickIn(buffer);
  }
}
