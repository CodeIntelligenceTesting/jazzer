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

package com.code_intelligence.jazzer.mutation.mutator.collection;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.ParameterizedTestUtils.prependArgs;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.asSet;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.getCallerMethodName;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.lang.reflect.AnnotatedType;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("unchecked")
class SetMutatorTest {
  static ChainedMutatorFactory factory;

  static final int DELETE_CHUNK = ChunkMutations.MutationAction.DELETE_CHUNK.ordinal();
  static final int INSERT_CHUNK = ChunkMutations.MutationAction.INSERT_CHUNK.ordinal();
  static final int MUTATE_CHUNK = ChunkMutations.MutationAction.MUTATE_CHUNK.ordinal();

  static final int CROSSOVER_INSERT = ChunkCrossOvers.CrossOverAction.INSERT_CHUNK.ordinal();
  static final int CROSSOVER_OVERWRITE = ChunkCrossOvers.CrossOverAction.OVERWRITE_CHUNK.ordinal();
  static final int CROSSOVER_CHUNK = ChunkCrossOvers.CrossOverAction.CROSS_OVER_CHUNK.ordinal();

  static final int MUT_INT = 2;

  @BeforeEach
  void createFactory() {
    factory =
        ChainedMutatorFactory.of(LangMutators.newFactories(), CollectionMutators.newFactories());
  }

  static Stream<Arguments> deleteChunks() {
    Stream<Arguments> base =
        Stream.of(
            // (DELETE_CHUNK, chunkSize, offset)
            arguments(false, arguments(DELETE_CHUNK, 1, 0), asSet(1, 2, 3, 4), asSet(2, 3, 4)),
            arguments(false, arguments(DELETE_CHUNK, 1, 1), asSet(1, 2, 3, 4), asSet(1, 3, 4)),
            arguments(false, arguments(DELETE_CHUNK, 1, 2), asSet(1, 2, 3, 4), asSet(1, 2, 4)),
            arguments(false, arguments(DELETE_CHUNK, 1, 3), asSet(1, 2, 3, 4), asSet(1, 2, 3)),
            arguments(false, arguments(DELETE_CHUNK, 2, 0), asSet(1, 2, 3, 4), asSet(3, 4)),
            // Deleting several times in a row
            arguments(
                true,
                arguments(DELETE_CHUNK, 1, 0, DELETE_CHUNK, 1, 0, DELETE_CHUNK, 1, 0),
                asSet(1, 2, 3, 4),
                asSet(4)),
            arguments(
                true,
                arguments(DELETE_CHUNK, 1, 3, DELETE_CHUNK, 1, 2, DELETE_CHUNK, 1, 1),
                asSet(1, 2, 3, 4),
                asSet(1)),
            arguments(
                true,
                arguments(DELETE_CHUNK, 1, 0, DELETE_CHUNK, 1, 2, DELETE_CHUNK, 1, 0),
                asSet(1, 2, 3, 4),
                asSet(3)),
            arguments(
                true,
                arguments(DELETE_CHUNK, 2, 1, DELETE_CHUNK, 1, 1),
                asSet(1, 2, 3, 4),
                asSet(1)));
    final AnnotatedType type = new TypeHolder<@NotNull Set<@NotNull Integer>>() {}.annotatedType();
    return prependArgs(base, getCallerMethodName(), type);
  }

  static Stream<Arguments> insertChunks() {
    Stream<Arguments> base =
        Stream.of(
            // (INSERT_CHUNK, chunkSize, select new and not specialValue (>= 4), newValue) -
            // IntegralMutators use .init() to generate new values
            arguments(
                false,
                arguments(INSERT_CHUNK, 1, 4, 10L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 3, 4, 10)),
            arguments(
                false,
                arguments(INSERT_CHUNK, 2, 4, 10L, 4, 20L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 3, 4, 10, 20)),
            arguments(
                false,
                arguments(INSERT_CHUNK, 3, 4, 10L, 4, 20L, 4, 30L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 3, 4, 10, 20, 30)),
            // Insert with retries due to duplicates
            arguments(
                false,
                arguments(INSERT_CHUNK, 1, 4, 1L, 4, 2L, 4, 3L, 4, 4L, 4, 10L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 3, 4, 10)),
            arguments(
                false,
                arguments(INSERT_CHUNK, 2, 4, 1L, 4, 2L, 4, 3L, 4, 4L, 4, 10L, 4, 20L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 3, 4, 10, 20)),
            arguments(
                false,
                arguments(INSERT_CHUNK, 3, 4, 1L, 4, 2L, 4, 30L, 4, 3L, 4, 4L, 4, 10L, 4, 20L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 3, 4, 10, 20, 30)));
    final AnnotatedType type = new TypeHolder<@NotNull Set<@NotNull Integer>>() {}.annotatedType();
    return prependArgs(base, getCallerMethodName(), type);
  }

  static Stream<Arguments> mutateRandomChunks() {
    Stream<Arguments> base =
        Stream.of(
            // (MUTATE_CHUNK, chunkSize, chunkOffset, MUT, newValue)
            arguments(
                false,
                arguments(MUTATE_CHUNK, 1, 0, MUT_INT, 10L),
                asSet(1, 2, 3, 4),
                asSet(2, 3, 4, 10)),
            arguments(
                false,
                arguments(MUTATE_CHUNK, 2, 0, MUT_INT, 10L, MUT_INT, 20L),
                asSet(1, 2, 3, 4),
                asSet(3, 4, 10, 20)),
            arguments(
                false,
                arguments(MUTATE_CHUNK, 2, 1, MUT_INT, 10L, MUT_INT, 20L),
                asSet(1, 2, 3, 4),
                asSet(1, 4, 10, 20)),
            arguments(
                false,
                arguments(MUTATE_CHUNK, 2, 2, MUT_INT, 10L, MUT_INT, 20L),
                asSet(1, 2, 3, 4),
                asSet(1, 2, 10, 20)),
            arguments(
                false,
                arguments(MUTATE_CHUNK, 3, 0, MUT_INT, 10L, MUT_INT, 20L, MUT_INT, 30L),
                asSet(1, 2, 3, 4),
                asSet(10, 20, 30, 4)),
            arguments(
                false,
                arguments(MUTATE_CHUNK, 3, 1, MUT_INT, 10L, MUT_INT, 20L, MUT_INT, 30L),
                asSet(1, 2, 3, 4),
                asSet(10, 20, 30, 1)));
    final AnnotatedType type = new TypeHolder<@NotNull Set<@NotNull Integer>>() {}.annotatedType();
    return prependArgs(base, "mutateRandomChunks", type);
  }

  static Stream<Arguments> mutateRandomChunksReachMaxRepetition() {
    final AnnotatedType bools = new TypeHolder<@NotNull Set<@NotNull Boolean>>() {}.annotatedType();
    Stream<Arguments> base =
        Stream.of(
            // (MUTATE_CHUNK, chunkSize, chunkOffset, MUT, newValue)
            arguments(
                bools,
                false,
                arguments(MUTATE_CHUNK, 1, 0),
                asSet(true, false),
                asSet(true, false)));
    return prependArgs(base, getCallerMethodName());
  }

  @ParameterizedTest(name = "{index} {0}: input={4}, expected={5}")
  @MethodSource({
    "deleteChunks",
    "insertChunks",
    "mutateRandomChunks",
    "mutateRandomChunksReachMaxRepetition"
  })
  void testMutatorOperations(
      String sourceName, // used for better readability of test names, ignored in method
      AnnotatedType type,
      boolean allowMultipleMutations,
      Arguments prngContent,
      Set<Integer> input,
      Set<Integer> expected) {
    SerializingMutator<Set<?>> mutator = (SerializingMutator<Set<?>>) factory.createOrThrow(type);
    Set<?> mutated = input;

    try (MockPseudoRandom prng = mockPseudoRandom(prngContent.get())) {
      do {
        mutated = mutator.mutate(mutated, prng);
      } while (allowMultipleMutations && !prng.isEmpty());

      assertThat(mutated).isEqualTo(expected);
    }
  }

  static Stream<Arguments> crossOverInsertChunks() {
    Stream<Arguments> base =
        Stream.of(
            // (CROSSOVER_INSERT, chunkSize, chunkOffset)
            arguments(
                arguments(CROSSOVER_INSERT, 1, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10)),
            arguments(
                arguments(CROSSOVER_INSERT, 1, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10)),
            arguments(
                arguments(CROSSOVER_INSERT, 1, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 20)),
            arguments(
                arguments(CROSSOVER_INSERT, 1, 3),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 30)),
            arguments(
                arguments(CROSSOVER_INSERT, 1, 4),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 40)),
            arguments(
                arguments(CROSSOVER_INSERT, 2, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10, 20)),
            arguments(
                arguments(CROSSOVER_INSERT, 2, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10, 20)),
            arguments(
                arguments(CROSSOVER_INSERT, 2, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 20, 30)),
            arguments(
                arguments(CROSSOVER_INSERT, 2, 3),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 30, 40)),
            arguments(
                arguments(CROSSOVER_INSERT, 3, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10, 20, 30)),
            arguments(
                arguments(CROSSOVER_INSERT, 3, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10, 20, 30)),
            arguments(
                arguments(CROSSOVER_INSERT, 3, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 20, 30, 40)),
            arguments(
                arguments(CROSSOVER_INSERT, 4, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10, 20, 30, 40)),
            arguments(
                arguments(CROSSOVER_INSERT, 4, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3, 10, 20, 30, 40)));
    final AnnotatedType type = new TypeHolder<@NotNull Set<@NotNull Integer>>() {}.annotatedType();
    return prependArgs(base, getCallerMethodName(), type);
  }

  static Stream<Arguments> crossOverOverwriteChunks() {
    Stream<Arguments> base =
        Stream.of(
            // (CROSSOVER_OVERWRITE, chunkSize, fromChunkOffset, toChunkOffset)
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 1, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(10, 2, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 2, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(20, 2, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 3, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(30, 2, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 4, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(40, 2, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 0, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 1, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 10, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 2, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 20, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 3, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 30, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 4, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 40, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 0, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 1, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 10)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 2, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 20)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 3, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 30)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 1, 4, 2),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 40)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 10, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 1, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(10, 20, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 2, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(20, 30, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 3, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(30, 40, 3)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 0, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 10)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 1, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 10, 20)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 2, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 20, 30)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 2, 3, 1),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 30, 40)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 3, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 10, 20)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 3, 1, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(10, 20, 30)),
            arguments(
                arguments(CROSSOVER_OVERWRITE, 3, 2, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(20, 30, 40)));
    final AnnotatedType type = new TypeHolder<@NotNull Set<@NotNull Integer>>() {}.annotatedType();
    return prependArgs(base, getCallerMethodName(), type);
  }

  static Stream<Arguments> crossOverCrossOver() {
    Stream<Arguments> base =
        Stream.of(
            // (CROSSOVER_CHUNK, chunkSize, fromChunkOffset, toChunkOffset, [cross over operation (0
            // == mean)]*)
            arguments(
                arguments(CROSSOVER_CHUNK, 1, 0, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 2, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 1, 1, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(5, 2, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 1, 2, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(10, 2, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 1, 3, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(15, 2, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 1, 4, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(20, 2, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 0, 0, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 6, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 1, 0, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(5, 11, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 2, 0, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(10, 16, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 3, 0, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(15, 21, 3)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 1, 1, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 6, 11)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 2, 1, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 11, 16)),
            arguments(
                arguments(CROSSOVER_CHUNK, 2, 3, 1, 0, 0),
                asSet(1, 2, 3),
                asSet(1, 10, 20, 30, 40),
                asSet(1, 16, 21)));
    final AnnotatedType type = new TypeHolder<@NotNull Set<@NotNull Integer>>() {}.annotatedType();
    return prependArgs(base, getCallerMethodName(), type);
  }

  @ParameterizedTest(name = "{index} {0}: input={3}, otherInput={4}, expected={5}")
  @MethodSource({"crossOverInsertChunks", "crossOverOverwriteChunks", "crossOverCrossOver"})
  void testCrossoverOperations(
      String sourceName, // used for better readability of test names, ignored in method
      AnnotatedType type,
      Arguments prngContent,
      Set<Integer> input1,
      Set<Integer> input2,
      Set<Integer> expected) {
    SerializingMutator<Set<?>> mutator = (SerializingMutator<Set<?>>) factory.createOrThrow(type);
    try (MockPseudoRandom prng = mockPseudoRandom(prngContent.get())) {
      Set<?> crossedOver = mutator.crossOver(input1, input2, prng);
      assertThat(crossedOver).isEqualTo(expected);
    }
  }
}
