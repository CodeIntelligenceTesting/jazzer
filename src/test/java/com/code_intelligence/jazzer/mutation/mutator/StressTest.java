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

package com.code_intelligence.jazzer.mutation.mutator;

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithZeros;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.lang.Math.floor;
import static java.lang.Math.pow;
import static java.lang.Math.sqrt;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.stream.IntStream.rangeClosed;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.protobuf.Proto3.BytesField3;
import com.code_intelligence.jazzer.protobuf.Proto3.IntegralField3;
import com.code_intelligence.jazzer.protobuf.Proto3.OptionalPrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedIntegralField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedRecursiveMessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.StringField3;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class StressTest {
  private static final int NUM_INITS = 1000;
  private static final int NUM_MUTATE_PER_INIT = 100;
  private static final double MANY_DISTINCT_ELEMENTS_RATIO = 0.5;

  public static Stream<Arguments> stressTestCases() {
    return Stream.of(arguments(asAnnotatedType(boolean.class), "Boolean", exactly(false, true),
                         exactly(false, true)),
        arguments(new TypeHolder<@NotNull Boolean>() {}.annotatedType(), "Boolean",
            exactly(false, true), exactly(false, true)),
        arguments(new TypeHolder<Boolean>() {}.annotatedType(), "Nullable<Boolean>",
            exactly(null, false, true), exactly(null, false, true)),
        arguments(new TypeHolder<@NotNull List<@NotNull Boolean>>() {}.annotatedType(),
            "List<Boolean>", exactly(emptyList(), singletonList(false), singletonList(true)),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull List<Boolean>>() {}.annotatedType(),
            "List<Nullable<Boolean>>",
            exactly(emptyList(), singletonList(null), singletonList(false), singletonList(true)),
            manyDistinctElements()),
        arguments(new TypeHolder<List<@NotNull Boolean>>() {}.annotatedType(),
            "Nullable<List<Boolean>>",
            exactly(null, emptyList(), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.30)),
        arguments(new TypeHolder<List<Boolean>>() {}.annotatedType(),
            "Nullable<List<Nullable<Boolean>>>",
            exactly(
                null, emptyList(), singletonList(null), singletonList(false), singletonList(true)),
            distinctElementsRatio(0.30)),
        arguments(asAnnotatedType(byte.class), "Byte",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1 << Byte.SIZE, boundHits(NUM_INITS, 0.2)),
                contains((byte) 0, (byte) 1, Byte.MIN_VALUE, Byte.MAX_VALUE)),
            // With mutations, we expect to reach all possible bytes.
            exactly(rangeClosed(Byte.MIN_VALUE, Byte.MAX_VALUE).mapToObj(i -> (byte) i).toArray())),
        arguments(asAnnotatedType(short.class), "Short",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1 << Short.SIZE, boundHits(NUM_INITS, 0.2)),
                contains((short) 0, (short) 1, Short.MIN_VALUE, Short.MAX_VALUE)),
            // The integral type mutator does not always return uniformly random values and the
            // random walk it uses is more likely to produce non-distinct elements, hence the test
            // only passes with ~90% of the optimal parameters.
            expectedNumberOfDistinctElements(
                1 << Short.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(asAnnotatedType(int.class), "Integer",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1L << Integer.SIZE, boundHits(NUM_INITS, 0.2)),
                contains(0, 1, Integer.MIN_VALUE, Integer.MAX_VALUE)),
            // See "Short" case.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(new TypeHolder<@NotNull @InRange(min = 0) Long>() {}.annotatedType(), "Long",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1L << Long.SIZE - 1, boundHits(NUM_INITS, 0.2)),
                contains(0L, 1L, Long.MAX_VALUE)),
            // See "Short" case.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE - 1, NUM_INITS * NUM_MUTATE_PER_INIT * 9 / 10)),
        arguments(
            new TypeHolder<@NotNull @InRange(max = Integer.MIN_VALUE + 5) Integer>() {
            }.annotatedType(),
            "Integer",
            exactly(rangeClosed(Integer.MIN_VALUE, Integer.MIN_VALUE + 5).boxed().toArray()),
            exactly(rangeClosed(Integer.MIN_VALUE, Integer.MIN_VALUE + 5).boxed().toArray())));
  }

  public static Stream<Arguments> protoStressTestCases() {
    return Stream.of(
        arguments(new TypeHolder<@NotNull OptionalPrimitiveField3>() {}.annotatedType(),
            "{Builder.Nullable<Boolean>} -> Message",
            exactly(OptionalPrimitiveField3.newBuilder().build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(false).build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(true).build()),
            exactly(OptionalPrimitiveField3.newBuilder().build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(false).build(),
                OptionalPrimitiveField3.newBuilder().setSomeField(true).build())),
        arguments(new TypeHolder<@NotNull RepeatedRecursiveMessageField3>() {}.annotatedType(),
            "{Builder.Boolean, Builder via List<(cycle)>} -> Message",
            contains(RepeatedRecursiveMessageField3.getDefaultInstance(),
                RepeatedRecursiveMessageField3.newBuilder().setSomeField(true).build(),
                RepeatedRecursiveMessageField3.newBuilder()
                    .addMessageField(RepeatedRecursiveMessageField3.getDefaultInstance())
                    .build(),
                RepeatedRecursiveMessageField3.newBuilder()
                    .addMessageField(RepeatedRecursiveMessageField3.newBuilder().setSomeField(true))
                    .build()),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull IntegralField3>() {}.annotatedType(),
            "{Builder.Integer} -> Message",
            // init is heavily biased towards special values and only returns a uniformly random
            // value in 1 out of 5 calls.
            all(expectedNumberOfDistinctElements(1L << Integer.SIZE, boundHits(NUM_INITS, 0.2)),
                contains(IntegralField3.newBuilder().build(),
                    IntegralField3.newBuilder().setSomeField(1).build(),
                    IntegralField3.newBuilder().setSomeField(Integer.MIN_VALUE).build(),
                    IntegralField3.newBuilder().setSomeField(Integer.MAX_VALUE).build())),
            // Our mutations return uniformly random elements in ~3/8 of all cases.
            expectedNumberOfDistinctElements(
                1L << Integer.SIZE, NUM_INITS * NUM_MUTATE_PER_INIT * 3 / 8)),
        arguments(new TypeHolder<@NotNull RepeatedIntegralField3>() {}.annotatedType(),
            "{Builder via List<Integer>} -> Message",
            contains(RepeatedIntegralField3.getDefaultInstance(),
                RepeatedIntegralField3.newBuilder().addSomeField(0).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(1).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(Integer.MAX_VALUE).build(),
                RepeatedIntegralField3.newBuilder().addSomeField(Integer.MIN_VALUE).build()),
            // TODO: This ratio is on the lower end, most likely because of the strong bias towards
            //  special values combined with the small initial size of the list. When we improve the
            //  list mutator, this may be increased.
            distinctElementsRatio(0.25)),
        arguments(new TypeHolder<@NotNull BytesField3>() {}.annotatedType(),
            "{Builder.byte[] -> ByteString} -> Message", manyDistinctElements(),
            manyDistinctElements()),
        arguments(new TypeHolder<@NotNull StringField3>() {}.annotatedType(),
            "{Builder.byte[] -> String} -> Message", manyDistinctElements(),
            manyDistinctElements()));
  }

  @SafeVarargs
  private static Consumer<List<Object>> all(Consumer<List<Object>>... checks) {
    return list -> {
      for (Consumer<List<Object>> check : checks) {
        check.accept(list);
      }
    };
  }

  private static Consumer<List<Object>> distinctElements(int num) {
    return list -> assertThat(new HashSet<>(list).size()).isAtLeast(num);
  }

  private static Consumer<List<Object>> manyDistinctElements() {
    return distinctElementsRatio(MANY_DISTINCT_ELEMENTS_RATIO);
  }

  /**
   * Returns a lower bound on the expected number of hits when sampling from a domain of a given
   * size with the given probability.
   */
  private static int boundHits(long domainSize, double probability) {
    // Binomial distribution.
    double expectedValue = domainSize * probability;
    double variance = domainSize * probability * (1 - probability);
    double standardDeviation = sqrt(variance);
    // Allow missing the expected value by two standard deviations. For a normal distribution,
    // this would correspond to 95% of all cases.
    int almostCertainLowerBound = (int) floor(expectedValue - 2 * standardDeviation);
    return almostCertainLowerBound;
  }

  /**
   * Asserts that a given list contains at least as many distinct elements as can be expected when
   * picking {@code picks} out of {@code domainSize} elements uniformly at random.
   */
  private static Consumer<List<Object>> expectedNumberOfDistinctElements(
      long domainSize, int picks) {
    // https://www.randomservices.org/random/urn/Birthday.html#mom2
    double expectedValue = domainSize * (1 - pow(1 - 1.0 / domainSize, picks));
    double variance = domainSize * (domainSize - 1) * pow(1 - 2.0 / domainSize, picks)
        + domainSize * pow(1 - 1.0 / domainSize, picks)
        - domainSize * domainSize * pow(1 - 1.0 / domainSize, 2 * picks);
    double standardDeviation = sqrt(variance);
    // Allow missing the expected value by two standard deviations. For a normal distribution,
    // this would correspond to 95% of all cases.
    int almostCertainLowerBound = (int) floor(expectedValue - 2 * standardDeviation);
    return list
        -> assertWithMessage("V=distinct elements among %s picked out of %s\nE[V]=%s\nσ[V]=%s",
            picks, domainSize, expectedValue, standardDeviation)
               .that(new HashSet<>(list).size())
               .isAtLeast(almostCertainLowerBound);
  }

  private static Consumer<List<Object>> distinctElementsRatio(double ratio) {
    require(ratio > 0);
    require(ratio <= 1);
    return list -> assertThat(new HashSet<>(list).size() / (double) list.size()).isAtLeast(ratio);
  }

  private static Consumer<List<Object>> exactly(Object... expected) {
    return list -> assertThat(new HashSet<>(list)).containsExactly(expected);
  }

  private static Consumer<List<Object>> contains(Object... expected) {
    return list -> assertThat(new HashSet<>(list)).containsAtLeastElementsIn(expected);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource({"stressTestCases", "protoStressTestCases"})
  void genericMutatorStressTest(AnnotatedType type, String mutatorTree,
      Consumer<List<Object>> expectedInitValues, Consumer<List<Object>> expectedMutatedValues)
      throws IOException {
    SerializingMutator mutator = Mutators.newFactory().createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo(mutatorTree);

    PseudoRandom rng = anyPseudoRandom();

    List<Object> initValues = new ArrayList<>();
    List<Object> mutatedValues = new ArrayList<>();
    for (int i = 0; i < NUM_INITS; i++) {
      Object value = mutator.init(rng);

      testReadWriteRoundtrip(mutator, value);
      testReadWriteExclusiveRoundtrip(mutator, value);

      initValues.add(mutator.detach(value));

      for (int mutation = 0; mutation < NUM_MUTATE_PER_INIT; mutation++) {
        Object detachedOldValue = mutator.detach(value);
        value = mutator.mutate(value, rng);
        assertThat(value).isNotEqualTo(detachedOldValue);

        testReadWriteRoundtrip(mutator, value);
        testReadWriteExclusiveRoundtrip(mutator, value);

        mutatedValues.add(mutator.detach(value));
      }
    }

    expectedInitValues.accept(initValues);
    expectedMutatedValues.accept(mutatedValues);
  }

  private static <T> void testReadWriteExclusiveRoundtrip(Serializer<T> serializer, T value)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    serializer.writeExclusive(value, out);
    T newValue = serializer.readExclusive(new ByteArrayInputStream(out.toByteArray()));
    assertThat(newValue).isEqualTo(value);
  }

  private static <T> void testReadWriteRoundtrip(Serializer<T> serializer, T value)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    serializer.write(value, new DataOutputStream(out));
    T newValue = serializer.read(
        new DataInputStream(extendWithZeros(new ByteArrayInputStream(out.toByteArray()))));
    assertThat(newValue).isEqualTo(value);
  }
}
