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

import static com.google.common.truth.Truth.assertThat;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.counting;
import static java.util.stream.Collectors.groupingBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.google.common.truth.Correspondence;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class SeededPseudoRandomTest {
  static Stream<Arguments> doubleClosedRange() {
    return Stream.of(
        arguments(Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, false),
        arguments(Double.MAX_VALUE, Double.POSITIVE_INFINITY, false),
        arguments(Double.NEGATIVE_INFINITY, -Double.MAX_VALUE, false),
        arguments(-Double.MAX_VALUE, Double.MAX_VALUE, false),
        arguments(-Double.MAX_VALUE, -Double.MAX_VALUE, false),
        arguments(-Double.MAX_VALUE * 0.5, Double.MAX_VALUE * 0.5, false),
        arguments(-Double.MAX_VALUE * 0.5, Math.nextUp(Double.MAX_VALUE * 0.5), false),
        arguments(Double.MAX_VALUE, Double.MAX_VALUE, false),
        arguments(-Double.MIN_VALUE, Double.MIN_VALUE, false),
        arguments(-Double.MIN_VALUE, 0, false),
        arguments(0, Double.MIN_VALUE, false),
        arguments(-Double.MAX_VALUE, 0, false),
        arguments(0, Double.MAX_VALUE, false),
        arguments(1000.0, Double.MAX_VALUE, false),
        arguments(0, Double.POSITIVE_INFINITY, false),
        arguments(1e200, Double.POSITIVE_INFINITY, false),
        arguments(Double.NEGATIVE_INFINITY, -1e200, false),
        arguments(0.0, 1.0, false),
        arguments(-1.0, 1.0, false),
        arguments(-1e300, 1e300, false),
        arguments(0.0, 0.0 + Double.MIN_VALUE, false),
        arguments(-Double.MAX_VALUE, -Double.MAX_VALUE + 1e292, false),
        arguments(-Double.NaN, 0.0, true),
        arguments(0.0, Double.NaN, true),
        arguments(Double.NaN, Double.NaN, true));
  }

  static Stream<Arguments> floatClosedRange() {
    return Stream.of(
        arguments(Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, false),
        arguments(Float.MAX_VALUE, Float.POSITIVE_INFINITY, false),
        arguments(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, false),
        arguments(-Float.MAX_VALUE, Float.MAX_VALUE, false),
        arguments(-Float.MAX_VALUE, -Float.MAX_VALUE, false),
        arguments(Float.MAX_VALUE, Float.MAX_VALUE, false),
        arguments(-Float.MAX_VALUE / 2f, Float.MAX_VALUE / 2f, false),
        arguments(-Float.MIN_VALUE, Float.MIN_VALUE, false),
        arguments(-Float.MIN_VALUE, 0f, false),
        arguments(0f, Float.MIN_VALUE, false),
        arguments(-Float.MAX_VALUE, 0f, false),
        arguments(0f, Float.MAX_VALUE, false),
        arguments(-Float.MAX_VALUE, -0f, false),
        arguments(-0f, Float.MAX_VALUE, false),
        arguments(1000f, Float.MAX_VALUE, false),
        arguments(0f, Float.POSITIVE_INFINITY, false),
        arguments(1e38f, Float.POSITIVE_INFINITY, false),
        arguments(Float.NEGATIVE_INFINITY, -1e38f, false),
        arguments(0f, 1f, false),
        arguments(-1f, 1f, false),
        arguments(-1e38f, 1e38f, false),
        arguments(0f, 0f + Float.MIN_VALUE, false),
        arguments(-Float.MAX_VALUE, -Float.MAX_VALUE + 1e32f, false),
        arguments(-Float.NaN, 0f, true),
        arguments(0f, Float.NaN, true),
        arguments(Float.NaN, Float.NaN, true));
  }

  @ParameterizedTest
  @MethodSource("doubleClosedRange")
  void testDoubleForceInRange(double minValue, double maxValue, boolean throwsException) {
    SeededPseudoRandom seededPseudoRandom = new SeededPseudoRandom(1337);
    for (int i = 0; i < 1000; i++) {
      if (throwsException) {
        assertThrows(
            IllegalArgumentException.class,
            () -> seededPseudoRandom.closedRange(minValue, maxValue),
            "minValue: " + minValue + ", maxValue: " + maxValue);
      } else {
        double inClosedRange = seededPseudoRandom.closedRange(minValue, maxValue);
        assertThat(inClosedRange).isAtLeast(minValue);
        assertThat(inClosedRange).isAtMost(maxValue);
        assertThat(inClosedRange).isFinite();
      }
    }
  }

  @ParameterizedTest
  @MethodSource("floatClosedRange")
  void testFloatForceInRange(float minValue, float maxValue, boolean throwsException) {
    SeededPseudoRandom seededPseudoRandom = new SeededPseudoRandom(1337);
    for (int i = 0; i < 1000; i++) {
      if (throwsException) {
        assertThrows(
            IllegalArgumentException.class,
            () -> seededPseudoRandom.closedRange(minValue, maxValue),
            "minValue: " + minValue + ", maxValue: " + maxValue);
      } else {
        float inClosedRange = seededPseudoRandom.closedRange(minValue, maxValue);
        assertThat(inClosedRange).isAtLeast(minValue);
        assertThat(inClosedRange).isAtMost(maxValue);
        assertThat(inClosedRange).isFinite();
      }
    }
  }

  @Test
  void testClosedRangeBiasedTowardsSmall() {
    SeededPseudoRandom prng = new SeededPseudoRandom(1337133371337L);

    assertThrows(IllegalArgumentException.class, () -> prng.sizeInClosedRange(2, 1, false));
    assertThrows(IllegalArgumentException.class, () -> prng.sizeInClosedRange(2, 1, true));
    assertThat(prng.sizeInClosedRange(5, 5, false)).isEqualTo(5);
    assertThat(prng.sizeInClosedRange(5, 5, true)).isEqualTo(5);
  }

  @Test
  void testClosedRangeBiasedTowardsSmall_distribution() {
    int num = 5000000;
    SeededPseudoRandom prng = new SeededPseudoRandom(1337133371337L);
    Map<Integer, Double> frequencies =
        Stream.generate(() -> prng.sizeInClosedRange(0, 9, false))
            .limit(num)
            .collect(
                groupingBy(i -> i, collectingAndThen(counting(), count -> ((double) count) / num)));
    // Reference values obtained from
    // https://www.wolframalpha.com/input?i=N%5BTable%5BPDF%5BZipfDistribution%5B10%2C+1%5D%2C+i%5D%2C+%7Bi%2C+1%2C+10%7D%5D%5D
    assertThat(frequencies)
        .comparingValuesUsing(Correspondence.tolerance(0.0005))
        .containsExactly(
            0, 0.645, 1, 0.161, 2, 0.072, 3, 0.040, 4, 0.026, 5, 0.018, 6, 0.013, 7, 0.01, 8, 0.008,
            9, 0.006);
  }
}
