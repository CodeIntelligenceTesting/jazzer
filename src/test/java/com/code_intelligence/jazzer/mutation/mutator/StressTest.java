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
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
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
  private static final int GENERIC_TEST_ITERATIONS = 1000;
  private static final int GENERIC_TEST_MUTATIONS_PER_ITERATIONS = 100;
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
            distinctElementsRatio(0.30)));
  }

  private static Consumer<List<Object>> manyDistinctElements() {
    return distinctElementsRatio(MANY_DISTINCT_ELEMENTS_RATIO);
  }

  private static Consumer<List<Object>> distinctElementsRatio(double ratio) {
    require(ratio > 0);
    require(ratio <= 1);
    return list -> assertThat(new HashSet<>(list).size() / (double) list.size()).isAtLeast(ratio);
  }

  private static Consumer<List<Object>> exactly(Object... expected) {
    return list -> assertThat(new HashSet<>(list)).containsExactly(expected);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("stressTestCases")
  void genericMutatorStressTest(AnnotatedType type, String mutatorTree,
      Consumer<List<Object>> expectedInitValues, Consumer<List<Object>> expectedMutatedValues)
      throws IOException {
    SerializingMutator mutator = Mutators.newFactory().createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo(mutatorTree);

    PseudoRandom rng = anyPseudoRandom();

    List<Object> initValues = new ArrayList<>();
    List<Object> mutatedValues = new ArrayList<>();
    for (int i = 0; i < GENERIC_TEST_ITERATIONS; i++) {
      Object value = mutator.init(rng);

      testReadWriteRoundtrip(mutator, value);
      testReadWriteExclusiveRoundtrip(mutator, value);

      initValues.add(mutator.detach(value));

      for (int mutation = 0; mutation < GENERIC_TEST_MUTATIONS_PER_ITERATIONS; mutation++) {
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
