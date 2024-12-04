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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.mutator.lang.IntegralMutatorFactory.AbstractIntegralMutator.forceInRange;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("unchecked")
class IntegralMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory = ChainedMutatorFactory.of(LangMutators.newFactories());
  }

  static Stream<Arguments> forceInRangeCases() {
    return Stream.of(
        arguments(0, 0, 1),
        arguments(5, 0, 1),
        arguments(-5, -10, -1),
        arguments(-200, -10, -1),
        arguments(10, 0, 3),
        arguments(-5, 0, 3),
        arguments(10, -7, 7),
        arguments(Long.MIN_VALUE, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(Long.MIN_VALUE, Long.MIN_VALUE, 100),
        arguments(Long.MIN_VALUE + 100, Long.MIN_VALUE, 100),
        arguments(Long.MAX_VALUE, -100, Long.MAX_VALUE),
        arguments(Long.MAX_VALUE - 100, -100, Long.MAX_VALUE),
        arguments(Long.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE),
        arguments(Long.MIN_VALUE, Long.MIN_VALUE + 1, Long.MAX_VALUE),
        arguments(Long.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE - 1),
        arguments(Long.MIN_VALUE, Long.MAX_VALUE - 5, Long.MAX_VALUE),
        arguments(Long.MAX_VALUE, Long.MIN_VALUE, Long.MIN_VALUE + 5));
  }

  @ParameterizedTest
  @MethodSource("forceInRangeCases")
  void testForceInRange(long value, long minValue, long maxValue) {
    long inRange = forceInRange(value, minValue, maxValue);
    assertThat(inRange).isAtLeast(minValue);
    assertThat(inRange).isAtMost(maxValue);
    if (value >= minValue && value <= maxValue) {
      assertThat(inRange).isEqualTo(value);
    }
  }

  static Stream<Arguments> forceInRangeMinMaxCases() {
    return Stream.of(
        arguments(Long.MAX_VALUE, 0, Long.MAX_VALUE, Long.MAX_VALUE),
        arguments(Long.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE, Long.MAX_VALUE),
        arguments(Long.MIN_VALUE, Long.MIN_VALUE, Long.MAX_VALUE, Long.MIN_VALUE),
        arguments(0, Long.MIN_VALUE, Long.MAX_VALUE, 0),
        arguments(0, 0, 0, 0),
        arguments(1, 0, 1, 1));
  }

  @ParameterizedTest
  @MethodSource("forceInRangeMinMaxCases")
  void testForceInRangeMinMax(long value, long minValue, long maxValue, long expected) {
    assertThat(forceInRange(value, minValue, maxValue)).isEqualTo(expected);
  }

  @Test
  void testCrossOver() {
    SerializingMutator<Long> mutator =
        (SerializingMutator<Long>)
            factory.createOrThrow(new TypeHolder<@NotNull Long>() {}.annotatedType());
    // cross over mean values
    try (MockPseudoRandom prng = mockPseudoRandom(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) {
      assertThat(mutator.crossOver(0L, 0L, prng)).isEqualTo(0);
      assertThat(mutator.crossOver(0L, 2L, prng)).isEqualTo(1);
      assertThat(mutator.crossOver(1L, 2L, prng)).isEqualTo(1);
      assertThat(mutator.crossOver(1L, 3L, prng)).isEqualTo(2);
      assertThat(mutator.crossOver(Long.MAX_VALUE, Long.MAX_VALUE, prng)).isEqualTo(Long.MAX_VALUE);

      assertThat(mutator.crossOver(0L, -2L, prng)).isEqualTo(-1);
      assertThat(mutator.crossOver(-1L, -2L, prng)).isEqualTo(-1);
      assertThat(mutator.crossOver(-1L, -3L, prng)).isEqualTo(-2);
      assertThat(mutator.crossOver(Long.MIN_VALUE, Long.MIN_VALUE, prng)).isEqualTo(Long.MIN_VALUE);

      assertThat(mutator.crossOver(-100L, 200L, prng)).isEqualTo(50);
      assertThat(mutator.crossOver(100L, -200L, prng)).isEqualTo(-50);
      assertThat(mutator.crossOver(Long.MIN_VALUE, Long.MAX_VALUE, prng)).isEqualTo(0);
    }
  }
}
