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

package com.code_intelligence.jazzer.runtime;

import java.nio.ByteBuffer;

/**
 * Represents the Java view on a libFuzzer 8 bit counter coverage map.
 * By using a direct ByteBuffer, the counter array is shared directly with
 * native code.
 */
final public class CoverageMap {
  // This needs to be a power of two to ensure two indices XORed together
  // don't overflow the buffer.
  public static int SIZE = 65536;
  public static ByteBuffer mem = ByteBuffer.allocateDirect(SIZE);
  @SuppressWarnings("unused") public static int prev_location = 0; // is used in byte code directly

  private static int nextPowerOfTwo(int minSize) {
    int nextPowerOfTwo = 1;
    // Cannot represent 2^31 in a signed int.
    for (int log2 = 0; log2 < 30; log2++) {
      nextPowerOfTwo <<= 1;
      if (nextPowerOfTwo >= minSize)
        break;
    }
    return nextPowerOfTwo;
  }

  public static void reinit(int minSize) {
    SIZE = nextPowerOfTwo(minSize);
    mem = ByteBuffer.allocateDirect(SIZE);
  }
}
