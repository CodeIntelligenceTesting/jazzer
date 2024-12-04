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
import static java.util.Collections.emptyList;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
public class ListMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory =
        ChainedMutatorFactory.of(LangMutators.newFactories(), CollectionMutators.newFactories());
  }

  private SerializingMutator<@NotNull List<@NotNull Integer>> defaultListMutator() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();
    return (SerializingMutator<@NotNull List<@NotNull Integer>>) factory.createOrThrow(type);
  }

  @Test
  void testInit() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();
    assertThat(mutator.toString()).isEqualTo("List<Integer>");

    List<Integer> list;
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // targetSize
            1,
            // elementMutator.init
            1)) {
      list = mutator.init(prng);
    }
    assertThat(list).containsExactly(0);
  }

  @Test
  void testInitMaxSize() {
    AnnotatedType type =
        new TypeHolder<
            @NotNull @WithSize(min = 2, max = 3) List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) factory.createOrThrow(type);

    assertThat(mutator.toString()).isEqualTo("List<Integer>");
    List<Integer> list;
    try (MockPseudoRandom prng = mockPseudoRandom(2, 4, 42L, 4, 43L)) {
      list = mutator.init(prng);
    }

    assertThat(list).containsExactly(42, 43).inOrder();
  }

  @Test
  void testRemoveSingleElement() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            0,
            // number of elements to remove
            1,
            // index to remove
            2)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testRemoveChunk() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            0,
            // chunk size
            2,
            // chunk offset
            3)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testAddSingleElement() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));
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
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 4, 5, 6, 7, 8, 9, 42).inOrder();
  }

  @Test
  void testAddChunk() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));
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
            42L)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 42, 42, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testChangeSingleElement() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            2,
            // number of elements to mutate
            1,
            // first index to mutate at
            2,
            // mutation choice based on `IntegralMutatorFactory`
            // 2 == closedRange
            2,
            // value
            55L)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 55, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testChangeChunk() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // action
            2,
            // Mutate a chunk instead of a single element.
            8,
            // number of elements to mutate
            2,
            // first index to mutate at
            5,
            // mutation: 0 == bitflip
            0,
            // shift constant
            13,
            // and again
            0,
            12)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 4, 5, 8198, 4103, 8, 9, 10, 11).inOrder();
  }

  @Test
  void testCrossOverEmptyLists() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      List<Integer> list = mutator.crossOver(emptyList(), emptyList(), prng);
      assertThat(list).isEmpty();
    }
  }

  @Test
  void testCrossOverInsertChunk() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
    List<Integer> otherList =
        new ArrayList<>(Arrays.asList(10, 11, 12, 13, 14, 15, 16, 17, 18, 19));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // insert action
            0,
            // chunk size
            3,
            // fromPos
            2,
            // toPos
            5)) {
      list = mutator.crossOver(list, otherList, prng);
    }
    assertThat(list).containsExactly(0, 1, 2, 3, 4, 12, 13, 14, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testCrossOverInsertChunk_chunkBiggerThanList() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(emptyList());
    List<Integer> otherList = new ArrayList<>(Arrays.asList(10, 11, 12));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // insert action
            0,
            // chunk size
            2,
            // fromPos
            1,
            // toPos
            0)) {
      list = mutator.crossOver(list, otherList, prng);
    }
    assertThat(list).containsExactly(11, 12).inOrder();
  }

  @Test
  void testCrossOverOverwriteChunk() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
    List<Integer> otherList =
        new ArrayList<>(Arrays.asList(10, 11, 12, 13, 14, 15, 16, 17, 18, 19));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // overwrite action
            1,
            // chunk size
            3,
            // fromPos
            2,
            // toPos
            5)) {
      list = mutator.crossOver(list, otherList, prng);
    }
    assertThat(list).containsExactly(0, 1, 2, 3, 4, 12, 13, 14, 8, 9).inOrder();
  }

  @Test
  void testCrossOverCrossOverChunk() {
    SerializingMutator<@NotNull List<@NotNull Integer>> mutator = defaultListMutator();

    List<Integer> list = new ArrayList<>(Arrays.asList(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
    List<Integer> otherList =
        new ArrayList<>(Arrays.asList(10, 11, 12, 13, 14, 15, 16, 17, 18, 19));
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // overwrite action
            2,
            // chunk size
            3,
            // fromPos
            2,
            // toPos
            2,
            // mean value in sub cross over
            0,
            // mean value in sub cross over
            0,
            // mean value in sub cross over
            0)) {
      list = mutator.crossOver(list, otherList, prng);
    }
    assertThat(list).containsExactly(0, 1, 7, 8, 9, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void propagateConstraint() {
    SerializingMutator<@NotNull List<List<Integer>>> mutator =
        (SerializingMutator<@NotNull List<List<Integer>>>)
            factory.createOrThrow(
                new TypeHolder<
                    @NotNull(constraint = PropertyConstraint.RECURSIVE) List<
                        List<Integer>>>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("List<List<Integer>>");
  }
}
