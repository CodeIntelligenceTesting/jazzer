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

import static com.code_intelligence.jazzer.mutation.mutator.lang.FloatingPointMutatorFactory.DoubleMutator;
import static com.code_intelligence.jazzer.mutation.mutator.lang.FloatingPointMutatorFactory.FloatMutator;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TestSupport;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class FloatingPointMutatorTest {
  static ChainedMutatorFactory createFactory() {
    return ChainedMutatorFactory.of(LangMutators.newFactories());
  }

  static final Float UNUSED_FLOAT = 0.0f;
  static final Double UNUSED_DOUBLE = 0.0;

  static Stream<Arguments> floatForceInRangeCases() {
    float NaN1 = Float.intBitsToFloat(0x7f800001);
    float NaN2 = Float.intBitsToFloat(0x7f800002);
    float NaN3 = Float.intBitsToFloat(0x7f800003);
    assertThat(Float.isNaN(NaN1) && Float.isNaN(NaN2) && Float.isNaN(NaN3)).isTrue();

    return Stream.of(
        // value is already in range: it should stay in range
        arguments(0.0f, 0.0f, 1.0f, true),
        arguments(0.0f, 1.0f, 1.0f, true),
        arguments(Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY, 1.0f, true),
        arguments(Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, true),
        arguments(Float.NaN, 0.0f, 1.0f, true),
        arguments(1e30f, -Float.MAX_VALUE, Float.MAX_VALUE, true),
        arguments(-1e30f, -Float.MAX_VALUE, Float.MAX_VALUE, true),
        arguments(0.0f, Float.NEGATIVE_INFINITY, Float.MAX_VALUE, true),
        arguments(0.0f, Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, true),
        arguments(-Float.MAX_VALUE, -Float.MAX_VALUE, Float.MAX_VALUE, true),
        arguments(Float.MAX_VALUE, -Float.MAX_VALUE, Float.MAX_VALUE, true),
        arguments(-Float.MAX_VALUE, Float.MAX_VALUE - 3.4e30f, Float.MAX_VALUE, false),
        arguments(Float.MAX_VALUE, -100.0f, Float.MAX_VALUE, true),
        arguments(0.0f, -Float.MIN_VALUE, Float.MIN_VALUE, true),
        // Special values and diff/ranges outside the range
        arguments(Float.NEGATIVE_INFINITY, -1.0f, 1.0f, true),
        arguments(Float.POSITIVE_INFINITY, -1.0f, 1.0f, true),
        arguments(Float.POSITIVE_INFINITY, -Float.MAX_VALUE, Float.MAX_VALUE, true),
        arguments(Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, Float.MAX_VALUE, true),
        arguments(Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, true),
        arguments(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, Float.MAX_VALUE, true),
        arguments(Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, Float.POSITIVE_INFINITY, true),
        arguments(Float.NEGATIVE_INFINITY, Float.MAX_VALUE, Float.POSITIVE_INFINITY, true),
        // Values outside the range
        arguments(-2e30f, -100000.0f, 100000.0f, true),
        arguments(2e30f, Float.NEGATIVE_INFINITY, -Float.MAX_VALUE, true),
        arguments(-1.0f, 0.0f, 1.0f, false),
        arguments(5.0f, 0.0f, 1.0f, false),
        arguments(-Float.MAX_VALUE, -Float.MAX_VALUE, 100.0f, true),
        // NaN not allowed
        arguments(Float.NaN, 0.0f, 1.0f, false),
        arguments(Float.NaN, -Float.MAX_VALUE, 1.0f, false),
        arguments(Float.NaN, Float.NEGATIVE_INFINITY, 1.0f, false),
        arguments(Float.NaN, Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, false),
        arguments(Float.NaN, 0f, Float.POSITIVE_INFINITY, false),
        arguments(Float.NaN, 0f, Float.MAX_VALUE, false),
        arguments(Float.NaN, -Float.MAX_VALUE, Float.MAX_VALUE, false),
        arguments(Float.NaN, -Float.MIN_VALUE, 0.0f, false),
        arguments(Float.NaN, -Float.MIN_VALUE, Float.MIN_VALUE, false),
        arguments(Float.NaN, 0.0f, Float.MIN_VALUE, false),
        // There are many possible NaN values, test a few of them that are different from Float.NaN
        // (0x7fc00000)
        arguments(NaN1, 0.0f, 1.0f, false),
        arguments(NaN2, 0.0f, 1.0f, false),
        arguments(NaN3, 0.0f, 1.0f, false));
  }

  static Stream<Arguments> doubleForceInRangeCases() {
    double NaN1 = Double.longBitsToDouble(0x7ff0000000000001L);
    double NaN2 = Double.longBitsToDouble(0x7ff0000000000002L);
    double NaN3 = Double.longBitsToDouble(0x7ff0000000000003L);
    double NaNdeadbeef = Double.longBitsToDouble(0x7ff00000deadbeefL);
    assertThat(
            Double.isNaN(NaN1)
                && Double.isNaN(NaN2)
                && Double.isNaN(NaN3)
                && Double.isNaN(NaNdeadbeef))
        .isTrue();

    return Stream.of(
        // value is already in range: it should stay in range
        arguments(0.0, 0.0, 1.0, true),
        arguments(0.0, 1.0, 1.0, true),
        arguments(Double.NEGATIVE_INFINITY, Double.NEGATIVE_INFINITY, 1.0, true),
        arguments(
            Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, true),
        arguments(Double.NaN, 0.0, 1.0, true),
        arguments(1e30, -Double.MAX_VALUE, Double.MAX_VALUE, true),
        arguments(-1e30, -Double.MAX_VALUE, Double.MAX_VALUE, true),
        arguments(0.0, Double.NEGATIVE_INFINITY, Double.MAX_VALUE, true),
        arguments(0.0, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, true),
        arguments(-Double.MAX_VALUE, -Double.MAX_VALUE, Double.MAX_VALUE, true),
        arguments(Double.MAX_VALUE, -Double.MAX_VALUE, Double.MAX_VALUE, true),
        arguments(-Double.MAX_VALUE, Double.MAX_VALUE - 3.4e30, Double.MAX_VALUE, false),
        arguments(Double.MAX_VALUE, -100.0, Double.MAX_VALUE, true),
        arguments(0.0, -Double.MIN_VALUE, Double.MIN_VALUE, true),
        // Special values and diff/ranges outside the range
        arguments(Double.NEGATIVE_INFINITY, -1.0, 1.0, true),
        arguments(Double.POSITIVE_INFINITY, -1.0, 1.0, true),
        arguments(Double.POSITIVE_INFINITY, -Double.MAX_VALUE, Double.MAX_VALUE, true),
        arguments(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Double.MAX_VALUE, true),
        arguments(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -Double.MAX_VALUE, true),
        arguments(Double.NEGATIVE_INFINITY, -Double.MAX_VALUE, Double.MAX_VALUE, true),
        arguments(Double.NEGATIVE_INFINITY, -Double.MAX_VALUE, Double.POSITIVE_INFINITY, true),
        arguments(Double.NEGATIVE_INFINITY, Double.MAX_VALUE, Double.POSITIVE_INFINITY, true),
        // Values outside the range
        arguments(-2e30, -100000.0, 100000.0, true),
        arguments(2e30, Double.NEGATIVE_INFINITY, -Double.MAX_VALUE, true),
        arguments(-1.0, 0.0, 1.0, false),
        arguments(5.0, 0.0, 1.0, false),
        arguments(-Double.MAX_VALUE, -Double.MAX_VALUE, 100.0, true),
        arguments(
            Math.nextDown(Double.MAX_VALUE), -Double.MAX_VALUE * 0.5, Double.MAX_VALUE * 0.5, true),
        arguments(
            Math.nextDown(Double.MAX_VALUE),
            -Double.MAX_VALUE * 0.5,
            Math.nextUp(Double.MAX_VALUE * 0.5),
            true),
        // NaN not allowed
        arguments(Double.NaN, 0.0, 1.0, false),
        arguments(Double.NaN, -Double.MAX_VALUE, 1.0, false),
        arguments(Double.NaN, Double.NEGATIVE_INFINITY, 1.0, false),
        arguments(Double.NaN, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, false),
        arguments(Double.NaN, 0, Double.POSITIVE_INFINITY, false),
        arguments(Double.NaN, 0, Double.MAX_VALUE, false),
        arguments(Double.NaN, -Double.MAX_VALUE, Double.MAX_VALUE, false),
        arguments(Double.NaN, -Double.MIN_VALUE, 0.0, false),
        arguments(Double.NaN, -Double.MIN_VALUE, Double.MIN_VALUE, false),
        arguments(Double.NaN, 0.0, Double.MIN_VALUE, false),
        // There are many possible NaN values, test a few of them that are different from Double.NaN
        // (0x7ff8000000000000L)
        arguments(NaN1, 0.0, 1.0, false),
        arguments(NaN2, 0.0, 1.0, false),
        arguments(NaN3, 0.0, 1.0, false),
        arguments(NaNdeadbeef, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, false));
  }

  @ParameterizedTest
  @MethodSource("floatForceInRangeCases")
  void testFloatForceInRange(float value, float minValue, float maxValue, boolean allowNaN) {
    float inRange = FloatMutator.forceInRange(value, minValue, maxValue, allowNaN);

    // inRange can become NaN only if allowNaN is true and value was NaN already
    if (Float.isNaN(inRange)) {
      if (allowNaN) {
        assertThat(Float.isNaN(value)).isTrue();
        return; // NaN is not in range of anything
      } else {
        throw new AssertionError("NaN is not allowed but was returned");
      }
    }

    assertThat(inRange).isAtLeast(minValue);
    assertThat(inRange).isAtMost(maxValue);
    if (value >= minValue && value <= maxValue) {
      assertThat(inRange).isEqualTo(value);
    }
  }

  @Test
  void testFloatForceInRangeMinMax() {
    boolean allowNaN = true;
    assertThat(FloatMutator.forceInRange(1.0f, 0.0f, 1.0f, allowNaN)).isEqualTo(1.0f);
    assertThat(FloatMutator.forceInRange(0.0f, 0.0f, 1.0f, allowNaN)).isEqualTo(0.0f);
    assertThat(DoubleMutator.forceInRange(Double.MAX_VALUE, 10.0, Double.MAX_VALUE, allowNaN))
        .isEqualTo(Double.MAX_VALUE);
    assertThat(DoubleMutator.forceInRange(0.0, 0.0, Double.MAX_VALUE, allowNaN)).isEqualTo(0.0);
    assertThat(
            DoubleMutator.forceInRange(
                -Double.MAX_VALUE, -Double.MAX_VALUE, Double.MAX_VALUE, allowNaN))
        .isEqualTo(-Double.MAX_VALUE);
  }

  @ParameterizedTest
  @MethodSource("doubleForceInRangeCases")
  void testDoubleForceInRange(double value, double minValue, double maxValue, boolean allowNaN) {
    double inRange = DoubleMutator.forceInRange(value, minValue, maxValue, allowNaN);

    // inRange can become NaN only if allowNaN is true and value was NaN already
    if (Double.isNaN(inRange)) {
      if (allowNaN) {
        assertThat(Double.isNaN(value)).isTrue();
        return; // NaN is not in range of anything
      } else {
        throw new AssertionError("NaN is not allowed but was returned");
      }
    }

    assertThat(inRange).isAtLeast(minValue);
    assertThat(inRange).isAtMost(maxValue);
    if (value >= minValue && value <= maxValue) {
      assertThat(inRange).isEqualTo(value);
    }
  }

  // Tests of mutators' special values after initialization use mocked PRNG to test one special
  // value after another. This counter enables adding new special values and testcases for them
  // without modifying all the other test cases.
  static Supplier<Integer> makeCounter() {
    return new Supplier<Integer>() {
      private int counter = 0;

      @Override
      public Integer get() {
        return counter++;
      }
    };
  }

  static Stream<Arguments> floatInitCasesFullRange() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Float>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Float.NEGATIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.POSITIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_FLOAT, false));
  }

  static Stream<Arguments> floatInitCasesMinusOneToOne() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @FloatInRange(min = -1.0f, max = 1.0f)
                        Float>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), -1.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), 1.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_FLOAT, false));
  }

  static Stream<Arguments> floatInitCasesMinusMinToMin() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @FloatInRange(min = -Float.MIN_VALUE, max = Float.MIN_VALUE)
                        Float>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_FLOAT, false));
  }

  static Stream<Arguments> floatInitCasesMaxToInf() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @FloatInRange(min = Float.MAX_VALUE, max = Float.POSITIVE_INFINITY)
                        Float>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Float.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.POSITIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_FLOAT, false));
  }

  static Stream<Arguments> floatInitCasesMinusInfToMinusMax() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @FloatInRange(min = Float.NEGATIVE_INFINITY, max = -Float.MAX_VALUE)
                        Float>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Float.NEGATIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_FLOAT, false));
  }

  static Stream<Arguments> floatInitCasesFullRangeWithoutNaN() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @FloatInRange(
                            min = Float.NEGATIVE_INFINITY,
                            max = Float.POSITIVE_INFINITY,
                            allowNaN = true)
                        Float>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Float.NEGATIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0f, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.POSITIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), Float.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_FLOAT, false));
  }

  @ParameterizedTest
  @MethodSource({
    "floatInitCasesMinusOneToOne",
    "floatInitCasesFullRange",
    "floatInitCasesMinusMinToMin",
    "floatInitCasesMaxToInf",
    "floatInitCasesMinusInfToMinusMax",
    "floatInitCasesFullRangeWithoutNaN"
  })
  void testFloatInitCases(
      SerializingMutator<Float> mutator,
      Stream<Object> prngValues,
      float expected,
      boolean specialValueIndexExists) {
    assertThat(mutator.toString()).isEqualTo("Float");
    if (specialValueIndexExists) {
      Float n = null;
      try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(prngValues.toArray())) {
        n = mutator.init(prng);
      }
      assertThat(n).isEqualTo(expected);
    } else { // should throw
      assertThrows(
          AssertionError.class,
          () -> {
            try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(prngValues.toArray())) {
              mutator.init(prng);
            }
          });
    }
  }

  static Stream<Arguments> floatMutateSanityChecksFullRangeCases() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @FloatInRange(
                            min = Float.NEGATIVE_INFINITY,
                            max = Float.POSITIVE_INFINITY,
                            allowNaN = true)
                        Float>() {}.annotatedType());
    // Init value can be set to desired one by giving this to the init method: (false, <desired
    // value>)
    return Stream.of(
        // Bit flips
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 0, 0), 1.4e-45f, true),
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 0, 30), 2.0f, true),
        arguments(mutator, Stream.of(false, 2f), Stream.of(false, 0, 31), -2.0f, true),
        arguments(mutator, Stream.of(false, -2f), Stream.of(false, 0, 22), -3.0f, true),
        // mutateExponent
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 1, 0B01111100), 0.125f, true),
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 1, 0B01111110), 0.5f, true),
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 1, 0B01111111), 1.0f, true),
        // mutateMantissa
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 2, 0, 100), 1.4e-43f, true),
        arguments(
            mutator,
            Stream.of(false, Float.intBitsToFloat(1)),
            Stream.of(false, 2, 0, -1),
            0,
            true),
        // mutateWithMathematicalFn
        arguments(
            mutator, Stream.of(false, 10.1f), Stream.of(false, 3, 4), 11f, true), // Math::ceil
        arguments(
            mutator, Stream.of(false, 1000f), Stream.of(false, 3, 11), 3f, true), // Math::log10
        // skip libfuzzer
        // random in range
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 5, 10f), 10f, true),
        // unknown mutation case exception
        arguments(mutator, Stream.of(false, 0f), Stream.of(false, 6), UNUSED_FLOAT, false));
  }

  static Stream<Arguments> floatMutateLimitedRangeCases() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @FloatInRange(min = -1f, max = 1f, allowNaN = false)
                        Float>() {}.annotatedType());
    // Init value can be set to desired one by giving this to the init method: (false, <desired
    // value>)
    return Stream.of(
        // Bit flip; forceInRange(); result equals previous value; adjust value
        arguments(
            mutator,
            Stream.of(false, 0f),
            Stream.of(false, 0, 30, true),
            0f - Float.MIN_VALUE,
            true),
        arguments(mutator, Stream.of(false, 1f), Stream.of(false, 0, 30), Math.nextDown(1f), true),
        arguments(mutator, Stream.of(false, -1f), Stream.of(false, 0, 30), Math.nextUp(-1f), true),
        // NaN after mutateWithMathematicalFn with NaN not allowed; forceInRange will return
        // (min+max)/2
        arguments(mutator, Stream.of(false, -1f), Stream.of(false, 3, 16), 0.0f, true));
  }

  static Stream<Arguments> floatMutateLimitedRangeCasesWithNaN() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @FloatInRange(min = -1f, max = 1f, allowNaN = true)
                        Float>() {}.annotatedType());
    // Init value can be set to desired one by giving this to the init method: (false, <desired
    // value>)
    return Stream.of(
        // NaN after mutation and forceInRange(); all good!
        arguments(mutator, Stream.of(false, -1f), Stream.of(false, 3, 16), Float.NaN, true),
        // NaN (with a set bit #8) after init, mutation, and forceInRange(); need to change NaN to
        // something else
        arguments(mutator, Stream.of(true, 6), Stream.of(false, 0, 8, 0.3f), 0.3f, true));
  }

  @ParameterizedTest
  @MethodSource({
    "floatMutateSanityChecksFullRangeCases",
    "floatMutateLimitedRangeCases",
    "floatMutateLimitedRangeCasesWithNaN"
  })
  void testFloatMutateCases(
      SerializingMutator<Float> mutator,
      Stream<Object> initValues,
      Stream<Object> mutationValues,
      float expected,
      boolean knownMutatorSwitchCase) {
    assertThat(mutator.toString()).isEqualTo("Float");
    Float n;

    // Init
    try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(initValues.toArray())) {
      n = mutator.init(prng);
    }

    // Mutate
    if (knownMutatorSwitchCase) {
      try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(mutationValues.toArray())) {
        n = mutator.mutate(n, prng);
      }
      assertThat(n).isEqualTo(expected);

      if (!((FloatMutator) mutator).allowNaN) {
        assertThat(n).isNotEqualTo(Float.NaN);
      }

      if (!Float.isNaN(n)) {
        assertThat(n).isAtLeast(((FloatMutator) mutator).minValue);
        assertThat(n).isAtMost(((FloatMutator) mutator).maxValue);
      }
    } else { // Invalid mutation because a case is not handled
      assertThrows(
          AssertionError.class,
          () -> {
            try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(mutationValues.toArray())) {
              mutator.mutate(UNUSED_FLOAT, prng);
            }
          });
    }
  }

  @Test
  void testFloatCrossOverMean() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Float>() {}.annotatedType());
    try (TestSupport.MockPseudoRandom prng =
        mockPseudoRandom(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) {
      assertThat(mutator.crossOver(0f, 0f, prng)).isWithin(0).of(0f);
      assertThat(mutator.crossOver(-0f, 0f, prng)).isWithin(0).of(0f);
      assertThat(mutator.crossOver(0f, 2f, prng)).isWithin(1e-10f).of(1.0f);
      assertThat(mutator.crossOver(1f, 2f, prng)).isWithin(1e-10f).of(1.5f);
      assertThat(mutator.crossOver(1f, 3f, prng)).isWithin(1e-10f).of(2f);
      assertThat(mutator.crossOver(Float.MAX_VALUE, Float.MAX_VALUE, prng))
          .isWithin(1e-10f)
          .of(Float.MAX_VALUE);

      assertThat(mutator.crossOver(0f, -2f, prng)).isWithin(1e-10f).of(-1.0f);
      assertThat(mutator.crossOver(-1f, -2f, prng)).isWithin(1e-10f).of(-1.5f);
      assertThat(mutator.crossOver(-1f, -3f, prng)).isWithin(1e-10f).of(-2f);
      assertThat(mutator.crossOver(-Float.MAX_VALUE, -Float.MAX_VALUE, prng))
          .isWithin(1e-10f)
          .of(-Float.MAX_VALUE);

      assertThat(mutator.crossOver(-100f, 200f, prng)).isWithin(1e-10f).of(50.0f);
      assertThat(mutator.crossOver(100f, -200f, prng)).isWithin(1e-10f).of(-50f);
      assertThat(mutator.crossOver(-Float.MAX_VALUE, Float.MAX_VALUE, prng))
          .isWithin(1e-10f)
          .of(0f);

      assertThat(mutator.crossOver(Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, prng)).isNaN();
      assertThat(mutator.crossOver(Float.POSITIVE_INFINITY, 0f, prng)).isPositiveInfinity();
      assertThat(mutator.crossOver(0f, Float.POSITIVE_INFINITY, prng)).isPositiveInfinity();
      assertThat(mutator.crossOver(Float.NEGATIVE_INFINITY, 0f, prng)).isNegativeInfinity();
      assertThat(mutator.crossOver(0f, Float.NEGATIVE_INFINITY, prng)).isNegativeInfinity();
      assertThat(mutator.crossOver(Float.NaN, 0f, prng)).isNaN();
      assertThat(mutator.crossOver(0f, Float.NaN, prng)).isNaN();
    }
  }

  @Test
  void testFloatCrossOverExponent() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Float>() {}.annotatedType());
    try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(1, 1, 1)) {
      assertThat(mutator.crossOver(2.0f, -1.5f, prng)).isWithin(1e-10f).of(1.0f);
      assertThat(mutator.crossOver(2.0f, Float.POSITIVE_INFINITY, prng)).isPositiveInfinity();
      assertThat(mutator.crossOver(-1.5f, Float.NEGATIVE_INFINITY, prng)).isNaN();
    }
  }

  @Test
  void testFloatCrossOverMantissa() {
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Float>() {}.annotatedType());
    try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(2, 2, 2)) {
      assertThat(mutator.crossOver(4.0f, 3.5f, prng)).isWithin(1e-10f).of(7.0f);
      assertThat(mutator.crossOver(Float.POSITIVE_INFINITY, 3.0f, prng)).isNaN();
      assertThat(mutator.crossOver(Float.MAX_VALUE, 0.0f, prng)).isWithin(1e-10f).of(1.7014118e38f);
    }
  }

  static Stream<Arguments> doubleInitCasesFullRange() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Double>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Double.NEGATIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.POSITIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_DOUBLE, false));
  }

  static Stream<Arguments> doubleInitCasesMinusOneToOne() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @DoubleInRange(min = -1.0, max = 1.0)
                        Double>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), -1.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), 1.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_DOUBLE, false));
  }

  static Stream<Arguments> doubleInitCasesMinusMinToMin() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @DoubleInRange(min = -Double.MIN_VALUE, max = Double.MIN_VALUE)
                        Double>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_DOUBLE, false));
  }

  static Stream<Arguments> doubleInitCasesMaxToInf() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @DoubleInRange(min = Double.MAX_VALUE, max = Double.POSITIVE_INFINITY)
                        Double>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Double.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.POSITIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_DOUBLE, false));
  }

  static Stream<Arguments> doubleInitCasesMinusInfToMinusMax() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @DoubleInRange(min = Double.NEGATIVE_INFINITY, max = -Double.MAX_VALUE)
                        Double>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Double.NEGATIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_DOUBLE, false));
  }

  static Stream<Arguments> doubleInitCasesFullRangeWithoutNaN() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @DoubleInRange(
                            min = Double.NEGATIVE_INFINITY,
                            max = Double.POSITIVE_INFINITY,
                            allowNaN = true)
                        Double>() {}.annotatedType());
    Supplier<Integer> ctr = makeCounter();
    return Stream.of(
        arguments(mutator, Stream.of(true, ctr.get()), Double.NEGATIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), -0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), 0.0, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.MAX_VALUE, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.POSITIVE_INFINITY, true),
        arguments(mutator, Stream.of(true, ctr.get()), Double.NaN, true),
        arguments(mutator, Stream.of(true, ctr.get()), UNUSED_DOUBLE, false));
  }

  @ParameterizedTest
  @MethodSource({
    "doubleInitCasesMinusOneToOne",
    "doubleInitCasesFullRange",
    "doubleInitCasesMinusMinToMin",
    "doubleInitCasesMaxToInf",
    "doubleInitCasesMinusInfToMinusMax",
    "doubleInitCasesFullRangeWithoutNaN"
  })
  void testDoubleInitCases(
      SerializingMutator<Double> mutator,
      Stream<Object> prngValues,
      double expected,
      boolean knownSwitchCase) {
    assertThat(mutator.toString()).isEqualTo("Double");
    if (knownSwitchCase) {
      Double n = null;
      try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(prngValues.toArray())) {
        n = mutator.init(prng);
      }
      assertThat(n).isEqualTo(expected);
    } else {
      assertThrows(
          AssertionError.class,
          () -> {
            try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(prngValues.toArray())) {
              mutator.init(prng);
            }
          });
    }
  }

  static Stream<Arguments> doubleMutateSanityChecksFullRangeCases() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @DoubleInRange(
                            min = Double.NEGATIVE_INFINITY,
                            max = Double.POSITIVE_INFINITY,
                            allowNaN = true)
                        Double>() {}.annotatedType());
    // Init value can be set to desired one by giving this to the init method: (false, <desired
    // value>)
    return Stream.of(
        // Bit flips
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 0, 0), Double.MIN_VALUE, true),
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 0, 62), 2.0, true),
        arguments(mutator, Stream.of(false, 2.0), Stream.of(false, 0, 63), -2.0, true),
        arguments(mutator, Stream.of(false, -2.0), Stream.of(false, 0, 51), -3.0, true),
        // mutateExponent
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 1, 0B1111111100), 0.125, true),
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 1, 0B1111111110), 0.5, true),
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 1, 0B1111111111), 1.0, true),
        // mutateMantissa
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 2, 0, 100L), 4.94e-322, true),
        arguments(
            mutator,
            Stream.of(false, Double.longBitsToDouble(1)),
            Stream.of(false, 2, 0, -1L),
            0,
            true),
        // mutateWithMathematicalFn
        arguments(mutator, Stream.of(false, 10.1), Stream.of(false, 3, 4), 11, true), // Math::ceil
        arguments(
            mutator, Stream.of(false, 1000.0), Stream.of(false, 3, 11), 3, true), // Math::log10
        // skip libfuzzer
        // random in range
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 5, 10.0), 10, true),
        // unknown mutation case exception
        arguments(mutator, Stream.of(false, 0.0), Stream.of(false, 6), UNUSED_DOUBLE, false));
  }

  static Stream<Arguments> doubleMutateLimitedRangeCases() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @DoubleInRange(min = -1, max = 1, allowNaN = false)
                        Double>() {}.annotatedType());
    // Init value can be set to desired one by giving this to the init method: (false, <desired
    // value>)
    return Stream.of(
        // Bit flip; forceInRange(); result equals previous value; adjust value
        arguments(
            mutator,
            Stream.of(false, 0.0),
            Stream.of(false, 0, 62, true),
            0.0 - Double.MIN_VALUE,
            true),
        arguments(
            mutator, Stream.of(false, 1.0), Stream.of(false, 0, 62), Math.nextDown(1.0), true),
        arguments(
            mutator, Stream.of(false, -1.0), Stream.of(false, 0, 62), Math.nextUp(-1.0), true),
        // NaN after mutateWithMathematicalFn: sqrt(-1.0); NaN not allowed; forceInRange will return
        // (min+max)/2
        arguments(mutator, Stream.of(false, -1.0), Stream.of(false, 3, 16), 0.0, true));
  }

  static Stream<Arguments> doubleMutateLimitedRangeCasesWithNaN() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @DoubleInRange(min = -1, max = 1, allowNaN = true)
                        Double>() {}.annotatedType());
    // Init value can be set to desired one by giving this to the init method: (false, <desired
    // value>)
    return Stream.of(
        // NaN after mutation and forceInRange(); all good!
        arguments(mutator, Stream.of(false, -1.0), Stream.of(false, 3, 16), Double.NaN, true),
        // NaN (with a set bit #8) after init, mutation, and forceInRange(); need to change NaN to
        // something else
        arguments(mutator, Stream.of(true, 6), Stream.of(false, 0, 8, 0.3), 0.3, true));
  }

  @ParameterizedTest
  @MethodSource({
    "doubleMutateSanityChecksFullRangeCases",
    "doubleMutateLimitedRangeCases",
    "doubleMutateLimitedRangeCasesWithNaN"
  })
  void testDoubleMutateCases(
      SerializingMutator<Double> mutator,
      Stream<Object> initValues,
      Stream<Object> mutationValues,
      double expected,
      boolean knownSwitchCase) {
    assertThat(mutator.toString()).isEqualTo("Double");
    Double n;

    // Init
    try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(initValues.toArray())) {
      n = mutator.init(prng);
    }

    // Mutate
    if (knownSwitchCase) {
      try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(mutationValues.toArray())) {
        n = mutator.mutate(n, prng);
      }
      assertThat(n).isEqualTo(expected);

      if (!((DoubleMutator) mutator).allowNaN) {
        assertThat(n).isNotEqualTo(Double.NaN);
      }

      if (!Double.isNaN(n)) {
        assertThat(n).isAtLeast(((DoubleMutator) mutator).minValue);
        assertThat(n).isAtMost(((DoubleMutator) mutator).maxValue);
      }
    } else { // Invalid mutation because a case is not handled
      assertThrows(
          AssertionError.class,
          () -> {
            try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(mutationValues.toArray())) {
              mutator.mutate(UNUSED_DOUBLE, prng);
            }
          });
    }
  }

  @Test
  void testDoubleCrossOverMean() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Double>() {}.annotatedType());
    try (TestSupport.MockPseudoRandom prng =
        mockPseudoRandom(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) {
      assertThat(mutator.crossOver(0.0, 0.0, prng)).isWithin(0).of(0f);
      assertThat(mutator.crossOver(-0.0, 0.0, prng)).isWithin(0).of(0f);
      assertThat(mutator.crossOver(0.0, 2.0, prng)).isWithin(1e-10f).of(1.0f);
      assertThat(mutator.crossOver(1.0, 2.0, prng)).isWithin(1e-10f).of(1.5f);
      assertThat(mutator.crossOver(1.0, 3.0, prng)).isWithin(1e-10f).of(2f);
      assertThat(mutator.crossOver(Double.MAX_VALUE, Double.MAX_VALUE, prng))
          .isWithin(1e-10f)
          .of(Double.MAX_VALUE);

      assertThat(mutator.crossOver(0.0, -2.0, prng)).isWithin(1e-10f).of(-1.0f);
      assertThat(mutator.crossOver(-1.0, -2.0, prng)).isWithin(1e-10f).of(-1.5f);
      assertThat(mutator.crossOver(-1.0, -3.0, prng)).isWithin(1e-10f).of(-2f);
      assertThat(mutator.crossOver(-Double.MAX_VALUE, -Double.MAX_VALUE, prng))
          .isWithin(1e-10f)
          .of(-Double.MAX_VALUE);

      assertThat(mutator.crossOver(-100.0, 200.0, prng)).isWithin(1e-10f).of(50.0f);
      assertThat(mutator.crossOver(100.0, -200.0, prng)).isWithin(1e-10f).of(-50f);
      assertThat(mutator.crossOver(-Double.MAX_VALUE, Double.MAX_VALUE, prng))
          .isWithin(1e-10f)
          .of(0f);

      assertThat(mutator.crossOver(Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, prng))
          .isNaN();
      assertThat(mutator.crossOver(Double.POSITIVE_INFINITY, 0.0, prng)).isPositiveInfinity();
      assertThat(mutator.crossOver(0.0, Double.POSITIVE_INFINITY, prng)).isPositiveInfinity();
      assertThat(mutator.crossOver(Double.NEGATIVE_INFINITY, 0.0, prng)).isNegativeInfinity();
      assertThat(mutator.crossOver(0.0, Double.NEGATIVE_INFINITY, prng)).isNegativeInfinity();
      assertThat(mutator.crossOver(Double.NaN, 0.0, prng)).isNaN();
      assertThat(mutator.crossOver(0.0, Double.NaN, prng)).isNaN();
    }
  }

  @Test
  void testDoubleCrossOverExponent() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Double>() {}.annotatedType());
    try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(1, 1, 1)) {
      assertThat(mutator.crossOver(2.0, -1.5, prng)).isWithin(1e-10f).of(1.0f);
      assertThat(mutator.crossOver(2.0, Double.POSITIVE_INFINITY, prng)).isPositiveInfinity();
      assertThat(mutator.crossOver(-1.5, Double.NEGATIVE_INFINITY, prng)).isNaN();
    }
  }

  @Test
  void testDoubleCrossOverMantissa() {
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            createFactory().createOrThrow(new TypeHolder<@NotNull Double>() {}.annotatedType());
    try (TestSupport.MockPseudoRandom prng = mockPseudoRandom(2, 2, 2)) {
      assertThat(mutator.crossOver(4.0, 3.5, prng)).isWithin(1e-10f).of(7.0f);
      assertThat(mutator.crossOver(Double.POSITIVE_INFINITY, 3.0, prng)).isNaN();
      assertThat(mutator.crossOver(Double.MAX_VALUE, 0.0, prng))
          .isWithin(1e-10f)
          .of(8.98846567431158e307);
    }
  }
}
