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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.asMap;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.lang.reflect.AnnotatedType;
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class MapMutatorTest {
  public static final MutatorFactory FACTORY =
      new ChainedMutatorFactory(LangMutators.newFactory(), CollectionMutators.newFactory());

  @Test
  void mapInitInsert() {
    AnnotatedType type =
        new TypeHolder<@NotNull @WithSize(max = 3) Map<@NotNull String, @NotNull String>>(){}
            .annotatedType();
    SerializingMutator<Map<String, String>> mutator =
        (SerializingMutator<Map<String, String>>) FACTORY.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<String,String>");

    // Initialize new map
    Map<String, String> map;
    try (MockPseudoRandom prng = mockPseudoRandom(
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
    try (MockPseudoRandom prng = mockPseudoRandom(
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
    AnnotatedType type =
        new TypeHolder<@NotNull Map<@NotNull Integer, @NotNull Integer>>() {}.annotatedType();
    SerializingMutator<Map<Integer, Integer>> mutator =
        (SerializingMutator<Map<Integer, Integer>>) FACTORY.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<Integer,Integer>");

    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng = mockPseudoRandom(
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
    AnnotatedType type =
        new TypeHolder<@NotNull Map<@NotNull Integer, @NotNull Integer>>() {}.annotatedType();
    SerializingMutator<Map<Integer, Integer>> mutator =
        (SerializingMutator<Map<Integer, Integer>>) FACTORY.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<Integer,Integer>");

    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng = mockPseudoRandom(
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
    AnnotatedType type =
        new TypeHolder<@NotNull Map<@NotNull Integer, @NotNull Integer>>() {}.annotatedType();
    SerializingMutator<Map<Integer, Integer>> mutator =
        (SerializingMutator<Map<Integer, Integer>>) FACTORY.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<Integer,Integer>");

    Map<Integer, Integer> map = asMap(1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60);

    try (MockPseudoRandom prng = mockPseudoRandom(
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
        (SerializingMutator<Map<Boolean, Boolean>>) FACTORY.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<Boolean,Boolean>");

    // No new keys can be generated for this map.
    Map<Boolean, Boolean> map = asMap(false, false, true, false);

    try (MockPseudoRandom prng = mockPseudoRandom(
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
}
