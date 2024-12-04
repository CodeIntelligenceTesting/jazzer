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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.reflect.AnnotatedType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ArrayMutatorTest {

  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory =
        ChainedMutatorFactory.of(LangMutators.newFactories(), CollectionMutators.newFactories());
  }

  private SerializingMutator<@NotNull Integer @NotNull []> defaultArrayMutator() {
    AnnotatedType type = new TypeHolder<@NotNull Integer @NotNull []>() {}.annotatedType();
    return (SerializingMutator<@NotNull Integer @NotNull []>) factory.createOrThrow(type);
  }

  @Test
  void testInit() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator =
        (SerializingMutator<@NotNull Integer @NotNull []>)
            factory.createOrThrow(
                new TypeHolder<@NotNull Integer @NotNull []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Integer[]");

    Integer[] arr;
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // targetSize
            1,
            // elementMutator.init
            1)) {
      arr = mutator.init(prng);
    }

    assertThat(arr).asList().containsExactly(0);
  }

  @Test
  void testDetach() {
    SerializingMutator<Integer[]> mutator =
        (SerializingMutator<Integer[]>)
            factory.createOrThrow(
                new TypeHolder<@NotNull Integer @NotNull []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Integer[]");

    Integer[] inited;
    Integer[] detached;
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // targetSize
            1,
            // elementMutator.init
            1)) {
      inited = mutator.init(prng);
      detached = mutator.detach(inited);
    }

    assertThat(detached).isInstanceOf(Integer[].class);
    assertThat(detached).isEqualTo(inited);
    assertThat(detached).isNotSameInstanceAs(inited);
  }

  @Test
  void testInitMaxLength() {
    AnnotatedType type =
        new TypeHolder<
            @NotNull Integer @NotNull @WithLength(min = 2, max = 3) []>() {}.annotatedType();

    SerializingMutator<@NotNull Integer @NotNull []> mutator =
        (SerializingMutator<@NotNull Integer @NotNull []>) factory.createOrThrow(type);

    assertThat(mutator.toString()).isEqualTo("Integer[]");
    Integer[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(2, 4, 42L, 4, 43L)) {
      arr = mutator.init(prng);
    }

    assertThat(arr).asList().containsExactly(42, 43).inOrder();
  }

  @Test
  void testRemoveSingleElement() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();

    Integer[] arr = new Integer[] {1, 2, 3, 4, 5, 6, 7, 8, 9};
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            0,
            // number of elements to remove
            1,
            // index to remove
            2)) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).asList().containsExactly(1, 2, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testRemoveChunk() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();

    Integer[] arr = new Integer[] {1, 2, 3, 4, 5, 6, 7, 8, 9};
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            0,
            // chunk size
            2,
            // chunk offset
            3)) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).asList().containsExactly(1, 2, 3, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testAddSingleElement() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();

    Integer[] arr = new Integer[] {1, 2, 3, 4, 5, 6, 7, 8, 9};
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            1,
            // add single element,
            1,
            // offset,
            9,
            // Integral initImpl sentinel value
            4,
            // value
            42L)) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).asList().containsExactly(1, 2, 3, 4, 5, 6, 7, 8, 9, 42).inOrder();
  }

  @Test
  void testAddChunk() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();

    Integer[] arr = new Integer[] {1, 2, 3, 4, 5, 6, 7, 8, 9};

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            1,
            // chunkSize
            2,
            // chunkOffset
            3,
            // Integral initImpl
            4,
            // val
            42L,
            // Integral initImpl
            4,
            // val
            43L)) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).asList().containsExactly(1, 2, 3, 42, 43, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testChangeSingleElement() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();

    Integer[] arr = new Integer[] {1, 2, 3, 4, 5, 6, 7, 8, 9};

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            2,
            // index to mutate at
            2,
            // mutation choice based on `IntegralMutatorFactory`
            // 2 == closedRange
            2,
            // value
            55L)) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).asList().containsExactly(1, 2, 55, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testCrossOverEmptyArrays() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action CROSSOVER - MUTATE (only one in actions list)
            0,
            // size
            1,
            // index
            0,
            // Integral initImpl
            4,
            // val
            42L)) {
      Integer[] arr = mutator.crossOver(new Integer[0], new Integer[0], prng);
      // chooses mutation?
      assertThat(arr).asList().containsExactly(42);
    }
  }

  @Test
  void testCrossOverMix() {
    SerializingMutator<@NotNull Integer @NotNull []> mutator = defaultArrayMutator();
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action CROSSOVER: MIX
            7,
            // length
            8,
            // take from the first array
            true,
            // 2 elements
            2,
            // take from the second array
            false,
            // 2 elements
            2,
            // 1st array
            true,
            // 3 elements
            3)) {
      Integer[] arr =
          mutator.crossOver(new Integer[] {0, 1, 2, 3, 4}, new Integer[] {5, 6, 7, 8, 9}, prng);
      // chooses mutation?
      assertThat(arr).asList().containsExactly(0, 1, 5, 6, 2, 3, 4, 7).inOrder();
    }
  }

  @Test
  void propagateConstraint() {
    SerializingMutator<@NotNull Integer[]> mutator =
        (SerializingMutator<@NotNull Integer[]>)
            factory.createOrThrow(
                new TypeHolder<
                    Integer @NotNull(constraint = PropertyConstraint.RECURSIVE)
                        []>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Integer[]");
  }
}
