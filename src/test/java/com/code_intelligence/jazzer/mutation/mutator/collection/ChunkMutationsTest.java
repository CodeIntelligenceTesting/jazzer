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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.asMap;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.asMutableList;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockInitializer;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockMutator;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static java.util.stream.Collectors.toCollection;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ChunkMutationsTest {
  @Test
  void testDeleteRandomChunk() {
    List<Integer> list = Stream.of(1, 2, 3, 4, 5, 6).collect(toList());

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      ChunkMutations.deleteRandomChunk(list, 2, prng, false);
    }
    assertThat(list).containsExactly(1, 2, 3, 6).inOrder();
  }

  @Test
  void testInsertRandomChunk() {
    List<String> list = Stream.of("1", "2", "3", "4", "5", "6").collect(toList());

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      ChunkMutations.insertRandomChunk(list, 10, mockInitializer(() -> "7", String::new), prng);
    }
    assertThat(list).containsExactly("1", "2", "3", "7", "7", "4", "5", "6").inOrder();
    String firstNewValue = list.get(3);
    String secondNewValue = list.get(4);
    assertThat(firstNewValue).isEqualTo(secondNewValue);
    // Verify that the individual new elements were detached.
    assertThat(firstNewValue).isNotSameInstanceAs(secondNewValue);
  }

  @Test
  void testInsertRandomChunkSet() {
    Set<Integer> set = Stream.of(1, 2, 3, 4, 5, 6).collect(toCollection(LinkedHashSet::new));

    Queue<Integer> initReturnValues =
        Stream.of(7, 7, 7, 8, 9, 9).collect(toCollection(ArrayDeque::new));
    boolean result;
    try (MockPseudoRandom prng = mockPseudoRandom(3)) {
      result =
          ChunkMutations.insertRandomChunk(
              set, set::add, 10, mockInitializer(initReturnValues::remove, v -> v), prng);
    }
    assertThat(result).isTrue();
    assertThat(set).containsExactly(1, 2, 3, 4, 5, 6, 7, 8, 9).inOrder();
  }

  @Test
  void testInsertRandomChunkSet_largeChunk() {
    Set<Integer> set = Stream.of(1, 2, 3, 4, 5, 6).collect(toCollection(LinkedHashSet::new));

    Queue<Integer> initReturnValues =
        IntStream.rangeClosed(1, 10000).boxed().collect(toCollection(ArrayDeque::new));
    boolean result;
    try (MockPseudoRandom prng = mockPseudoRandom(9994)) {
      result =
          ChunkMutations.insertRandomChunk(
              set, set::add, 10000, mockInitializer(initReturnValues::remove, v -> v), prng);
    }
    assertThat(result).isTrue();
    assertThat(set)
        .containsExactlyElementsIn(IntStream.rangeClosed(1, 10000).boxed().toArray())
        .inOrder();
  }

  @Test
  void testInsertRandomChunkSet_failsToConstructDistinctValues() {
    Set<Integer> set = Stream.of(1, 2, 3, 4, 5, 6).collect(toCollection(LinkedHashSet::new));

    Queue<Integer> initReturnValues =
        Stream.concat(Stream.of(7, 7, 7, 8), Stream.generate(() -> 7).limit(1000))
            .collect(toCollection(ArrayDeque::new));
    boolean result;
    try (MockPseudoRandom prng = mockPseudoRandom(3)) {
      result =
          ChunkMutations.insertRandomChunk(
              set, set::add, 10, mockInitializer(initReturnValues::remove, v -> v), prng);
    }
    assertThat(result).isFalse();
    assertThat(set).containsExactly(1, 2, 3, 4, 5, 6, 7, 8).inOrder();
  }

  @Test
  void testMutateChunk() {
    List<Integer> list = Stream.of(1, 2, 3, 4, 5, 6).collect(toList());

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      ChunkMutations.mutateRandomChunk(list, mockMutator(1, i -> 2 * i), prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 8, 10, 6).inOrder();
  }

  @Test
  void testMutateRandomValuesChunk() {
    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      ChunkMutations.mutateRandomValuesChunk(map, mockMutator(1, i -> 2 * i), prng);
    }
    assertThat(map).containsExactly(1, 10, 2, 20, 3, 30, 4, 80, 5, 100, 6, 60).inOrder();
  }

  @Test
  void testMutateRandomKeysChunk() {
    Map<List<Integer>, Integer> map =
        asMap(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(4),
            40,
            asMutableList(5),
            50,
            asMutableList(6),
            60);
    SerializingMutator<List<Integer>> keyMutator =
        mockMutator(
            null,
            list -> {
              List<Integer> newList = list.stream().map(i -> i + 1).collect(toList());
              list.clear();
              return newList;
            },
            ArrayList::new);

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      boolean result = ChunkMutations.mutateRandomKeysChunk(map, keyMutator, prng);
      assertThat(result).isTrue();
    }
    assertThat(map)
        .containsExactly(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(6),
            60,
            asMutableList(7),
            40,
            asMutableList(8),
            50)
        .inOrder();
  }

  @Test
  void testMutateRandomKeysChunk_failsToConstructSomeDistinctKeys() {
    Map<List<Integer>, Integer> map =
        asMap(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(4),
            40,
            asMutableList(5),
            50,
            asMutableList(6),
            60);
    SerializingMutator<List<Integer>> keyMutator =
        mockMutator(
            null,
            list -> {
              list.clear();
              List<Integer> newList = new ArrayList<>();
              newList.add(7);
              return newList;
            },
            ArrayList::new);

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      boolean result = ChunkMutations.mutateRandomKeysChunk(map, keyMutator, prng);
      assertThat(result).isTrue();
    }
    assertThat(map)
        .containsExactly(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(5),
            50,
            asMutableList(6),
            60,
            asMutableList(7),
            40)
        .inOrder();
  }

  @Test
  void testMutateRandomKeysChunk_failsToConstructAnyDistinctKeys() {
    Map<List<Integer>, Integer> map =
        asMap(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(4),
            40,
            asMutableList(5),
            50,
            asMutableList(6),
            60);
    SerializingMutator<List<Integer>> keyMutator =
        mockMutator(
            null,
            list -> {
              list.clear();
              List<Integer> newList = new ArrayList<>();
              newList.add(1);
              return newList;
            },
            ArrayList::new);

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      boolean result = ChunkMutations.mutateRandomKeysChunk(map, keyMutator, prng);
      assertThat(result).isFalse();
    }
    assertThat(map)
        .containsExactly(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(4),
            40,
            asMutableList(5),
            50,
            asMutableList(6),
            60)
        .inOrder();
  }

  @Test
  void testMutateRandomKeysChunk_nullKeyAndValue() {
    Map<List<Integer>, Integer> map =
        asMap(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(4),
            null,
            null,
            50,
            asMutableList(6),
            60);
    SerializingMutator<List<Integer>> keyMutator =
        mockMutator(
            null,
            list -> {
              if (list != null) {
                List<Integer> newList = list.stream().map(i -> i + 1).collect(toList());
                list.clear();
                return newList;
              } else {
                return asMutableList(10);
              }
            },
            list -> list != null ? new ArrayList<>(list) : null);

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      boolean result = ChunkMutations.mutateRandomKeysChunk(map, keyMutator, prng);
      assertThat(result).isTrue();
    }
    assertThat(map)
        .containsExactly(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(6),
            60,
            asMutableList(5),
            null,
            asMutableList(10),
            50)
        .inOrder();
  }

  @Test
  void testMutateRandomKeysChunk_mutateKeyToNull() {
    Map<List<Integer>, Integer> map =
        asMap(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(4),
            40,
            asMutableList(5),
            50,
            asMutableList(6),
            60);
    SerializingMutator<List<Integer>> keyMutator =
        mockMutator(null, list -> null, list -> list != null ? new ArrayList<>(list) : null);

    try (MockPseudoRandom prng = mockPseudoRandom(1, 3)) {
      boolean result = ChunkMutations.mutateRandomKeysChunk(map, keyMutator, prng);
      assertThat(result).isTrue();
    }
    assertThat(map)
        .containsExactly(
            asMutableList(1),
            10,
            asMutableList(2),
            20,
            asMutableList(3),
            30,
            asMutableList(5),
            50,
            asMutableList(6),
            60,
            null,
            40)
        .inOrder();
  }
}
