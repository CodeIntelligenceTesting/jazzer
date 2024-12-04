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

package com.code_intelligence.jazzer.mutation.engine;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import java.util.List;
import java.util.SplittableRandom;
import java.util.function.Supplier;

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
  public <T> T pickIn(T[] array) {
    return array[indexIn(array.length)];
  }

  @Override
  public <T> T pickIn(List<T> list) {
    return list.get(indexIn(list.size()));
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
    require(
        lowerInclusive <= upperInclusive,
        format(
            "closedRange(%d, %d): lowerInclusive should be <= upperInclusive",
            lowerInclusive, upperInclusive));
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

  // This function always returns a finite value
  @Override
  public float closedRange(float lowerInclusive, float upperInclusive) {
    require(lowerInclusive <= upperInclusive);
    if (lowerInclusive == upperInclusive) {
      require(Double.isFinite(lowerInclusive));
      return lowerInclusive;
    }
    // Special case: [Float.NEGATIVE_INFINITY, -Float.MAX_VALUE]
    if (lowerInclusive == Float.NEGATIVE_INFINITY && upperInclusive == -Float.MAX_VALUE)
      return -Float.MAX_VALUE;
    // Special case: [Float.MAX_VALUE, Float.POSITIVE_INFINITY]
    if (lowerInclusive == Float.MAX_VALUE && upperInclusive == Float.POSITIVE_INFINITY)
      return Float.MAX_VALUE;
    float limitedLower =
        lowerInclusive == Float.NEGATIVE_INFINITY ? -Float.MAX_VALUE : lowerInclusive;
    float limitedUpper =
        upperInclusive == Float.POSITIVE_INFINITY ? Float.MAX_VALUE : upperInclusive;

    // nextDouble(start, bound) is exclusive of bound, so we use Math.nextUp to extend the bound to
    // the next representable double. The maximal possible range of a float is always finite when
    // represented as a double. Therefore, we can safely use nextDouble and convert it to a float.
    return (float) random.nextDouble((double) limitedLower, Math.nextUp((double) limitedUpper));
  }

  // This function always returns a finite value
  @Override
  public double closedRange(double lowerInclusive, double upperInclusive) {
    require(lowerInclusive <= upperInclusive);
    if (lowerInclusive == upperInclusive) {
      require(Double.isFinite(lowerInclusive));
      return lowerInclusive;
    }
    // Special case: [Double.NEGATIVE_INFINITY, -Double.MAX_VALUE]
    if (lowerInclusive == Double.NEGATIVE_INFINITY && upperInclusive == -Double.MAX_VALUE)
      return -Double.MAX_VALUE;
    // Special case: [Double.MAX_VALUE, Double.POSITIVE_INFINITY)
    if (lowerInclusive == Double.MAX_VALUE && upperInclusive == Double.POSITIVE_INFINITY)
      return Double.MAX_VALUE;

    // nextDouble(start, bound) cannot deal with infinite values, so we need to limit them
    double limitedLower =
        lowerInclusive == Double.NEGATIVE_INFINITY ? -Double.MAX_VALUE : lowerInclusive;
    double limitedUpper =
        upperInclusive == Double.POSITIVE_INFINITY ? Double.MAX_VALUE : upperInclusive;

    // After limiting, the range may contain only a single value: return that
    if (limitedLower == limitedUpper) return limitedLower;

    // random.nextDouble() is exclusive of the upper bound. To include the upper bound,
    // we extend the bound to the next double value by using Math.nextUp(limitedUpper).
    double nextUpper =
        (limitedUpper == Double.MAX_VALUE) ? limitedUpper : Math.nextUp(limitedUpper);

    // This, however, leads to a problem when the upper bound is Double.MAX_VALUE, because the next
    // double after that is Double.POSITIVE_INFINITY. This case is treated the same as infinite
    // range case, in the else branch.
    boolean couldExtendRange = nextUpper != limitedUpper;

    // nextDouble(start, bound) can only deal with finite ranges
    if (Double.isFinite(nextUpper - limitedLower) && couldExtendRange) {
      double result = random.nextDouble(limitedLower, nextUpper);
      // Clamp random.nextDouble() to the upper bound.
      // This is a workaround for RandomSupport.nextDouble() that causes it to
      // return values greater than upper bound.
      // See https://bugs.openjdk.org/browse/JDK-8281183 for a list of affected JDK versions.
      if (result > limitedUpper) result = limitedUpper;
      return result;
    } else {
      // Ranges that exceeds the maximum representable double value, or ranges that could not be
      // extended scale a random n from range [0; 1] onto the range [limitLower, limitUpper]
      // limitedLower * (1 - n) + limitedUpper * n            - is the same as:
      // limitedLower + (limitedUpper - limitedLower) * n
      // limitedLower + range * n
      double n = random.nextDouble(0.0, Math.nextUp(1.0));
      return limitedLower * (1 - n) + limitedUpper * n;
    }
  }

  @Override
  public void bytes(byte[] bytes) {
    RandomSupport.nextBytes(random, bytes);
  }

  private int closedRangeBiasedTowardsSmall(int upperInclusive) {
    if (upperInclusive == 0) {
      return 0;
    }
    Preconditions.require(upperInclusive > 0);
    // Modified from (Apache-2.0)
    // https://github.com/abseil/abseil-cpp/blob/2927340217c37328319b5869285a6dcdbc13e7a7/absl/random/zipf_distribution.h
    // by inlining the values v = 1 and q = 2.
    final double kd = upperInclusive;
    final double hxm = zipf_h(kd + 0.5);
    final double h0x5 = -1.0 / 1.5;
    final double elogv_q = 1.0;
    final double hx0_minus_hxm = (h0x5 - elogv_q) - hxm;
    final double s = 0.46153846153846123;
    double k;
    while (true) {
      final double v = random.nextDouble();
      final double u = hxm + v * hx0_minus_hxm;
      final double x = zipf_hinv(u);
      k = Math.floor(x + 0.5);
      if (k > kd) {
        continue;
      }
      if (k - x <= s) {
        break;
      }
      final double h = zipf_h(k + 0.5);
      final double r = zipf_pow_negative_q(1.0 + k);
      if (u >= h - r) {
        break;
      }
    }
    return (int) k;
  }

  @Override
  public int sizeInClosedRange(
      int lowerInclusive, int upperInclusive, boolean elementsHaveFixedSize) {
    if (elementsHaveFixedSize) {
      return closedRange(lowerInclusive, upperInclusive);
    } else {
      return lowerInclusive + closedRangeBiasedTowardsSmall(upperInclusive - lowerInclusive);
    }
  }

  private static double zipf_h(double x) {
    return -1.0 / (x + 1.0);
  }

  private static double zipf_hinv(double x) {
    return -1.0 + -1.0 / x;
  }

  private static double zipf_pow_negative_q(double x) {
    return 1.0 / (x * x);
  }

  @Override
  public <T> T pickValue(
      T value, T otherValue, Supplier<T> supplier, int inverseSupplierFrequency) {
    if (trueInOneOutOf(inverseSupplierFrequency)) {
      return supplier.get();
    } else if (choice()) {
      return value;
    } else {
      return otherValue;
    }
  }

  @Override
  public long nextLong() {
    return random.nextLong();
  }
}
