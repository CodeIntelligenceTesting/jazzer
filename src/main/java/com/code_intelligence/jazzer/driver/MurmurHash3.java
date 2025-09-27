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

/*
 * TODO: add original license of MurmurHash3
 * - test correctness
 * - benchmark speed
 */
package com.code_intelligence.jazzer.driver;

import sun.misc.Unsafe;

public class MurmurHash3 {
  // use UNSAFE for speed
  private static final Unsafe UNSAFE;

  static {
    try {
      java.lang.reflect.Field singleoneInstanceField = Unsafe.class.getDeclaredField("theUnsafe");
      singleoneInstanceField.setAccessible(true);
      UNSAFE = (Unsafe) singleoneInstanceField.get(null);
    } catch (Exception e) {
      throw new RuntimeException("Could not initialize Unsafe", e);
    }
  }

  private static long ROTL64(long x, int r) {
    return (x << r) | (x >>> (64 - r));
  }

  public static String MurmurHash3_x64_128(final byte[] in, int seed) {
    final int nblocks = in.length / 16;

    long h1 = seed;
    long h2 = seed;

    final long c1 = 0x87c37b91114253d5L;
    final long c2 = 0x4cf5ad432745937fL;

    long offset = UNSAFE.arrayBaseOffset(byte[].class);

    for (int i = 0; i < nblocks; i++) {
      long k1 = UNSAFE.getLong(in, offset + i * 16);
      long k2 = UNSAFE.getLong(in, offset + i * 16 + 8);

      k1 *= c1;
      k1 = ROTL64(k1, 31);
      k1 *= c2;
      h1 ^= k1;

      h1 = ROTL64(h1, 27);
      h1 += h2;
      h1 = h1 * 5 + 0x52dce729;

      k2 *= c2;
      k2 = ROTL64(k2, 33);
      k2 *= c1;
      h2 ^= k2;

      h2 = ROTL64(h2, 31);
      h2 += h1;
      h2 = h2 * 5 + 0x38495ab5;
    }

    int at = nblocks * 16;
    int len = in.length;

    long k1 = 0;
    long k2 = 0;

    switch (len & 15) {
      case 15:
        k2 ^= ((long) in[at + 14]) << 48;
      case 14:
        k2 ^= ((long) in[at + 13]) << 40;
      case 13:
        k2 ^= ((long) in[at + 12]) << 32;
      case 12:
        k2 ^= ((long) in[at + 11]) << 24;
      case 11:
        k2 ^= ((long) in[at + 10]) << 16;
      case 10:
        k2 ^= ((long) in[at + 9]) << 8;
      case 9:
        k2 ^= in[at + 8];
        k2 *= c2;
        k2 = ROTL64(k2, 33);
        k2 *= c1;
        h2 ^= k2;

      case 8:
        k1 ^= ((long) in[at + 7]) << 56;
      case 7:
        k1 ^= ((long) in[at + 6]) << 48;
      case 6:
        k1 ^= ((long) in[at + 5]) << 40;
      case 5:
        k1 ^= ((long) in[at + 4]) << 32;
      case 4:
        k1 ^= ((long) in[at + 3]) << 24;
      case 3:
        k1 ^= ((long) in[at + 2]) << 16;
      case 2:
        k1 ^= ((long) in[at + 1]) << 8;
      case 1:
        k1 ^= in[at + 0];
        k1 *= c1;
        k1 = ROTL64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
    }

    h1 ^= len;
    h2 ^= len;

    h1 += h2;
    h2 += h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 += h2;
    h2 += h1;
    return String.format("%016x%016x", h1, h2);
  }

  private static long fmix64(long k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53L;
    k ^= k >> 33;
    return k;
  }
}
