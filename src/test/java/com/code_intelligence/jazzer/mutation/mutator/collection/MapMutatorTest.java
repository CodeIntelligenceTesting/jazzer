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
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Collections.emptyMap;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.reflect.AnnotatedType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class MapMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory =
        ChainedMutatorFactory.of(LangMutators.newFactories(), CollectionMutators.newFactories());
  }

  private SerializingMutator<Map<Integer, Integer>> defaultTestMapMutator() {
    AnnotatedType type =
        new TypeHolder<@NotNull Map<@NotNull Integer, @NotNull Integer>>() {}.annotatedType();
    return (SerializingMutator<Map<Integer, Integer>>) factory.createOrThrow(type);
  }

  @Test
  void mapInitInsert() {
    AnnotatedType type =
        new TypeHolder<
            @NotNull @WithSize(max = 3) Map<@NotNull String, @NotNull String>>() {}.annotatedType();
    SerializingMutator<Map<String, String>> mutator =
        (SerializingMutator<Map<String, String>>) factory.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<String, String>");

    // Initialize new map
    Map<String, String> map;
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // Initial map size
            1,
            // Key 1 size
            4,
            // Key 1 value
            "Key1".getBytes(),
            // Value size
            6,
            // Value value
            "Value1".getBytes())) {
      map = mutator.init(prng);
    }
    assertThat(map).containsExactly("Key1", "Value1");

    // Add 2 new entries
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // grow chunk
            1,
            // ChunkSize
            2,
            // Key 2 size
            4,
            // Key 2 value
            "Key2".getBytes(),
            // Value size
            6,
            // Value value
            "Value2".getBytes(),
            // Key 3 size
            4,
            // Key 3 value
            "Key3".getBytes(),
            // Value size
            6,
            // Value value
            "Value3".getBytes())) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).containsExactly("Key1", "Value1", "Key2", "Value2", "Key3", "Value3").inOrder();
  }

  @Test
  void mapDelete() {
    SerializingMutator<Map<Integer, Integer>> mutator = defaultTestMapMutator();
    assertThat(mutator.toString()).isEqualTo("Map<Integer, Integer>");

    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // delete chunk
            0,
            // chunk size
            2,
            // chunk position
            3)) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).containsExactly(1, 10, 2, 20, 3, 30, 6, 60).inOrder();
  }

  @Test
  void mapMutateValues() {
    SerializingMutator<Map<Integer, Integer>> mutator = defaultTestMapMutator();
    assertThat(mutator.toString()).isEqualTo("Map<Integer, Integer>");

    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // change chunk
            2,
            // mutate values,
            true,
            // chunk size
            2,
            // chunk position
            3,
            // uniform pick
            2,
            // random integer
            41L,
            // uniform pick
            2,
            // random integer
            51L)) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).containsExactly(1, 10, 2, 20, 3, 30, 4, 41, 5, 51, 6, 60).inOrder();
  }

  @Test
  void mapMutateKeys() {
    SerializingMutator<Map<Integer, Integer>> mutator = defaultTestMapMutator();
    assertThat(mutator.toString()).isEqualTo("Map<Integer, Integer>");

    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // change chunk
            2,
            // mutate keys,
            false,
            // chunk size
            2,
            // chunk position
            3,
            // uniform pick
            2,
            // integer
            7L,
            // uniform pick
            2,
            // random integer
            8L)) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).containsExactly(1, 10, 2, 20, 3, 30, 6, 60, 7, 40, 8, 50).inOrder();
  }

  @Test
  void mapMutateKeysFallbackToValues() {
    AnnotatedType type =
        new TypeHolder<@NotNull Map<@NotNull Boolean, @NotNull Boolean>>() {}.annotatedType();
    SerializingMutator<Map<Boolean, Boolean>> mutator =
        (SerializingMutator<Map<Boolean, Boolean>>) factory.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<Boolean, Boolean>");

    // No new keys can be generated for this map.
    Map<Boolean, Boolean> map = asMap(false, false, true, false);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // change chunk
            2,
            // mutate keys,
            false,
            // chunk size
            1,
            // chunk position
            0,
            // chunk size for fallback to mutate values
            2,
            // chunk position for fallback
            0)) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).containsExactly(false, true, true, true).inOrder();
  }

  @Test
  void testCrossOverEmptyMaps() {
    SerializingMutator<@NotNull Map<@NotNull Integer, @NotNull Integer>> mutator =
        defaultTestMapMutator();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      Map<Integer, Integer> map = mutator.crossOver(emptyMap(), emptyMap(), prng);
      assertThat(map).isEmpty();
    }
  }

  @Test
  void testCrossOverInsertChunk() {
    SerializingMutator<@NotNull Map<@NotNull Integer, @NotNull Integer>> mutator =
        defaultTestMapMutator();

    Map<Integer, Integer> map = asMap(1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6);
    Map<Integer, Integer> otherMap = asMap(1, 1, 2, 2, 3, 3, 40, 40, 50, 50, 60, 60);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // insert action
            0,
            // chunk size
            3,
            // from chunk offset, will skip first element of chunk as it is already present in map
            3)) {
      map = mutator.crossOver(map, otherMap, prng);
      assertThat(map)
          .containsExactly(1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 40, 40, 50, 50, 60, 60)
          .inOrder();
    }
  }

  @Test
  void testCrossOverInsertChunk_chunkBiggerThanMap() {
    SerializingMutator<@NotNull Map<@NotNull Integer, @NotNull Integer>> mutator =
        defaultTestMapMutator();

    Map<Integer, Integer> map = asMap(3, 3);
    Map<Integer, Integer> otherMap = asMap(1, 2, 3, 4, 5, 6, 7, 8);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // insert action
            0,
            // chunk size
            2,
            // from chunk offset, will skip first element of chunk as it is already present in map
            1)) {
      map = mutator.crossOver(map, otherMap, prng);
      assertThat(map).containsExactly(3, 3, 5, 6, 7, 8).inOrder();
    }
  }

  @Test
  void testCrossOverOverwriteChunk() {
    SerializingMutator<@NotNull Map<@NotNull Integer, @NotNull Integer>> mutator =
        defaultTestMapMutator();

    Map<Integer, Integer> map = asMap(1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6);
    Map<Integer, Integer> otherMap = asMap(1, 1, 2, 2, 3, 3, 40, 40, 50, 50, 60, 60);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // overwrite action
            1,
            // chunk size
            3,
            // from chunk offset
            2,
            // to chunk offset, will not change first element as values are equal
            2)) {
      map = mutator.crossOver(map, otherMap, prng);
      assertThat(map).containsExactly(1, 1, 2, 2, 3, 3, 4, 40, 5, 50, 6, 6).inOrder();
    }
  }

  @Test
  void testCrossOverCrossOverChunkKeys() {
    AnnotatedType type =
        new TypeHolder<
            @NotNull Map<@NotNull List<@NotNull Integer>, @NotNull Integer>>() {}.annotatedType();
    SerializingMutator<@NotNull Map<@NotNull List<@NotNull Integer>, @NotNull Integer>> mutator =
        (SerializingMutator<@NotNull Map<@NotNull List<@NotNull Integer>, @NotNull Integer>>)
            factory.createOrThrow(type);

    Map<List<Integer>, Integer> map =
        asMap(
            asMutableList(1),
            1,
            asMutableList(2),
            2,
            asMutableList(3),
            3,
            asMutableList(4),
            4,
            asMutableList(5),
            5,
            asMutableList(6),
            6);
    Map<List<Integer>, Integer> otherMap =
        asMap(
            asMutableList(1),
            1,
            asMutableList(2),
            2,
            asMutableList(3),
            3,
            asMutableList(40),
            4,
            asMutableList(50),
            5,
            asMutableList(60),
            6);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // cross over action
            2,
            // keys
            true,
            // chunk size
            3,
            // from chunk offset
            2,
            // to chunk offset,
            // first keys ("3") are equal and will be overwritten
            2,
            // first key, delegate to list cross over, overwrite 1 entry at offset 0 from offset 0
            1,
            1,
            0,
            0,
            // second key, delegate to list cross over, overwrite 1 entry at offset 0 from offset 0
            1,
            1,
            0,
            0,
            // third key, delegate to list cross over, overwrite 1 entry at offset 0 from offset 0
            1,
            1,
            0,
            0)) {
      map = mutator.crossOver(map, otherMap, prng);
      assertThat(map)
          .containsExactly(
              asMutableList(1),
              1,
              asMutableList(2),
              2,
              asMutableList(6),
              6,
              // Overwritten keys after here
              asMutableList(3),
              3,
              asMutableList(40),
              4,
              asMutableList(50),
              5)
          .inOrder();
    }
  }

  @Test
  void testCrossOverCrossOverChunkValues() {
    AnnotatedType type =
        new TypeHolder<
            @NotNull Map<@NotNull Integer, @NotNull List<@NotNull Integer>>>() {}.annotatedType();
    SerializingMutator<@NotNull Map<@NotNull Integer, @NotNull List<@NotNull Integer>>> mutator =
        (SerializingMutator<@NotNull Map<@NotNull Integer, @NotNull List<@NotNull Integer>>>)
            factory.createOrThrow(type);

    Map<Integer, List<Integer>> map =
        asMap(
            1,
            asMutableList(1),
            2,
            asMutableList(2),
            3,
            asMutableList(3),
            4,
            asMutableList(4),
            5,
            asMutableList(5),
            6,
            asMutableList(6));
    Map<Integer, List<Integer>> otherMap =
        asMap(
            1,
            asMutableList(1),
            2,
            asMutableList(2),
            3,
            asMutableList(30),
            40,
            asMutableList(40),
            50,
            asMutableList(50),
            60,
            asMutableList(60));

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // cross over action
            2,
            // values
            false,
            // chunk size
            3,
            // from chunk offset
            2,
            // to chunk offset,
            2,
            // first value, delegate to list cross over, overwrite 1 entry at offset 0 from offset 0
            1,
            1,
            0,
            0,
            // second value, delegate to list cross over, overwrite 1 entry at offset 0 from offset
            // 0
            1,
            1,
            0,
            0,
            // third value, delegate to list cross over, overwrite 1 entry at offset 0 from offset 0
            1,
            1,
            0,
            0)) {
      map = mutator.crossOver(map, otherMap, prng);
      assertThat(map)
          .containsExactly(
              1,
              asMutableList(1),
              2,
              asMutableList(2),
              3,
              asMutableList(30),
              4,
              asMutableList(40),
              5,
              asMutableList(50),
              6,
              asMutableList(6))
          .inOrder();
    }
  }

  @Test
  void propagateConstraint() {
    SerializingMutator<@NotNull Map<String, List<Integer>>> mutator =
        (SerializingMutator<@NotNull Map<String, List<Integer>>>)
            factory.createOrThrow(
                new TypeHolder<
                    @NotNull(constraint = PropertyConstraint.RECURSIVE) Map<
                        String, List<Integer>>>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Map<String, List<Integer>>");
  }
}
