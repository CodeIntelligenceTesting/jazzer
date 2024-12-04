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

package com.code_intelligence.jazzer.mutation.support;

import java.util.SplittableRandom;

public final class RandomSupport {
  private RandomSupport() {}

  /** Polyfill for {@link SplittableRandom#nextBytes(byte[])}, which is not available in Java 8. */
  public static void nextBytes(SplittableRandom random, byte[] bytes) {
    // Taken from the implementation contract
    // https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/random/RandomGenerator.html#nextBytes(byte%5B%5D)
    // for interoperability with the RandomGenerator interface available as of Java 17.
    int i = 0;
    int len = bytes.length;
    for (int words = len >> 3; words-- > 0; ) {
      long rnd = random.nextLong();
      for (int n = 8; n-- > 0; rnd >>>= Byte.SIZE) bytes[i++] = (byte) rnd;
    }
    if (i < len)
      for (long rnd = random.nextLong(); i < len; rnd >>>= Byte.SIZE) bytes[i++] = (byte) rnd;
  }

  /**
   * Clamp function for integers, which Java does not yet have
   *
   * @param value the value you want to clamp
   * @param min the minimum allowable value (inclusive)
   * @param max the maximum allowable value (inclusive)
   * @return Closest number to {@code value} within the range {@code [min, max]}
   */
  public static int clamp(int value, int min, int max) {
    return Math.min(Math.max(value, min), max);
  }

  /**
   * Clamp function for longs, which Java does not yet have
   *
   * @param value the value you want to clamp
   * @param min the minimum allowable value (inclusive)
   * @param max the maximum allowable value (inclusive)
   * @return Closest number to {@code value} within the range {@code [min, max]}
   */
  public static long clamp(long value, long min, long max) {
    return Math.min(Math.max(value, min), max);
  }
}
