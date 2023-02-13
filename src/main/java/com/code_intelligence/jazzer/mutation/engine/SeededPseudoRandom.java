/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.engine;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import java.util.List;
import java.util.SplittableRandom;

public final class SeededPseudoRandom implements PseudoRandom {
  // We use SplittableRandom instead of Random since it doesn't incur unnecessary synchronization
  // overhead and uses a much better RNG under the hood that can generate all long values.
  private final SplittableRandom random;

  public SeededPseudoRandom(long seed) {
    this.random = new SplittableRandom(seed);
  }

  @Override
  public boolean choice() {
    return random.nextBoolean();
  }

  @Override
  public boolean trueInOneOutOf(int inverseFrequencyTrue) {
    // Ensure that the outcome of the choice isn't fixed.
    require(inverseFrequencyTrue >= 2);
    return indexIn(inverseFrequencyTrue) == 0;
  }

  @Override
  public <T> int indexIn(T[] array) {
    return indexIn(array.length);
  }

  @Override
  public <T> int indexIn(List<T> list) {
    return indexIn(list.size());
  }

  @Override
  public int indexIn(int range) {
    require(range >= 1);
    // TODO: Replace random.nextInt(length) with the fast version of
    //  https://lemire.me/blog/2016/06/30/fast-random-shuffling/, which avoids a modulo operation.
    //  It's slightly more biased for large bounds, but indices and choices tend to be small and
    //  are generated frequently (e.g. when picking a submutator).
    return random.nextInt(range);
  }

  @Override
  public <T> int otherIndexIn(T[] array, int currentIndex) {
    return otherIndexIn(array.length, currentIndex);
  }

  @Override
  public int otherIndexIn(int range, int currentIndex) {
    int otherIndex = currentIndex + closedRange(1, range - 1);
    if (otherIndex < range) {
      return otherIndex;
    } else {
      return otherIndex - range;
    }
  }

  @Override
  public int closedRange(int lowerInclusive, int upperInclusive) {
    require(lowerInclusive <= upperInclusive);
    int range = upperInclusive - lowerInclusive + 1;
    if (range > 0) {
      return lowerInclusive + random.nextInt(range);
    } else {
      // The interval [lowerInclusive, upperInclusive] covers at least half of the
      // [Integer.MIN_VALUE, Integer.MAX_VALUE] range, fall back to rejection sampling with an
      // expected number of samples <= 2.
      int r;
      do {
        r = random.nextInt();
      } while (r < lowerInclusive);
      return r;
    }
  }

  @Override
  public long closedRange(long lowerInclusive, long upperInclusive) {
    require(lowerInclusive <= upperInclusive);
    if (upperInclusive < Long.MAX_VALUE) {
      // upperInclusive + 1 <= Long.MAX_VALUE
      return random.nextLong(lowerInclusive, upperInclusive + 1);
    } else if (lowerInclusive > 0) {
      // upperInclusive + 1 - lowerInclusive <= Long.MAX_VALUE
      return lowerInclusive + random.nextLong(upperInclusive + 1 - lowerInclusive);
    } else {
      // The interval [lowerInclusive, Long.MAX_VALUE] covers at least half of the
      // [Long.MIN_VALUE, Long.MAX_VALUE] range, fall back to rejection sampling with an expected
      // number of samples <= 2.
      long r;
      do {
        r = random.nextLong();
      } while (r < lowerInclusive);
      return r;
    }
  }

  @Override
  public void bytes(byte[] bytes) {
    RandomSupport.nextBytes(random, bytes);
  }
}
