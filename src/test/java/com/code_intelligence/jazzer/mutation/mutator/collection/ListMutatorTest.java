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

package com.code_intelligence.jazzer.mutation.mutator.collection;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ListMutatorTest {
  public static final MutatorFactory FACTORY = Mutators.newFactory();

  @Test
  void testInit() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    assertThat(mutator.toString()).isEqualTo("List<Integer>");

    List<Integer> list;
    try (MockPseudoRandom prng = mockPseudoRandom(
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
        new TypeHolder<@NotNull @WithSize(min = 2, max = 3) List<@NotNull Integer>>(){}
            .annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    assertThat(mutator.toString()).isEqualTo("List<Integer>");
    List<Integer> list;
    try (MockPseudoRandom prng = mockPseudoRandom(2, 4, 42L, 4, 43L)) {
      list = mutator.init(prng);
    }

    assertThat(list).containsExactly(42, 43);
  }

  @Test
  void testRemoveSingleElement() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));

    try (MockPseudoRandom prng = mockPseudoRandom(
             // action
             0,
             // number of elements to remove
             1,
             // index to remove
             2)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 4, 5, 6, 7, 8, 9);
  }

  @Test
  void testRemoveChunk() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));

    try (MockPseudoRandom prng = mockPseudoRandom(
             // action
             0,
             // chunk size
             2,
             // chunk offset
             3)) {
      list = mutator.mutate(list, prng);
    }

    assertThat(list).containsExactly(1, 2, 3, 6, 7, 8, 9);
  }

  @Test
  void testAddSingleElement() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));

    try (MockPseudoRandom prng = mockPseudoRandom(
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

    assertThat(list).containsExactly(1, 2, 3, 4, 5, 6, 7, 8, 9, 42);
  }

  @Test
  void testAddChunk() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));

    try (MockPseudoRandom prng = mockPseudoRandom(
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
    assertThat(list).containsExactly(1, 2, 3, 42, 42, 4, 5, 6, 7, 8, 9);
  }

  @Test
  void testChangeSingleElement() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9));

    try (MockPseudoRandom prng = mockPseudoRandom(
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
    assertThat(list).containsExactly(1, 2, 55, 4, 5, 6, 7, 8, 9);
  }

  @Test
  void testChangeChunk() {
    AnnotatedType type = new TypeHolder<@NotNull List<@NotNull Integer>>() {}.annotatedType();

    SerializingMutator<@NotNull List<@NotNull Integer>> mutator =
        (SerializingMutator<@NotNull List<@NotNull Integer>>) FACTORY.createOrThrow(type);

    List<Integer> list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11));

    try (MockPseudoRandom prng = mockPseudoRandom(
             // action
             2,
             // number of elements to mutate
             2,
             // first index to mutate at
             5,
             // mutation: 0 == bitflip
             0,
             // shift constant
             13,
             // and again
             0, 12)) {
      list = mutator.mutate(list, prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 4, 5, 8198, 4103, 8, 9, 10, 11);
  }
}
