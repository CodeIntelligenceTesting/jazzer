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
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class MapMutatorTest {
  public static final MutatorFactory FACTORY = Mutators.newFactory();

  @Test
  void mapWithMutableKeysAndValues() {
    AnnotatedType type =
        new TypeHolder<@NotNull Map<@NotNull String, @NotNull String>>() {}.annotatedType();
    SerializingMutator<Map<String, String>> mutator =
        (SerializingMutator<Map<String, String>>) FACTORY.createOrThrow(type);

    assertThat(mutator.toString()).isEqualTo("Map<String,String>");

    // Initialize new map
    Map<String, String> map;
    try (MockPseudoRandom prng = mockPseudoRandom(
             // Initial map size
             1,
             // Key size
             3,
             // Key value
             "Key".getBytes(),
             // Value size
             5,
             // Value value
             "Value".getBytes())) {
      map = mutator.init(prng);
    }
    assertThat(map).hasSize(1);
    assertThat(map.get("Key")).isEqualTo("Value");

    // Add new entry
    try (MockPseudoRandom prng = mockPseudoRandom(
             // Add new entry
             true,
             // New key size
             3,
             // Key value
             "New".getBytes(),
             // New value size
             3,
             // Value value
             "New".getBytes())) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).hasSize(2);
    assertThat(map.get("New")).isEqualTo("New");

    // Mutate "New" entry
    try (MockPseudoRandom prng = mockPseudoRandom(
             // Mutate entry
             false,
             // Index
             0,
             // Mutate value
             false)) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).hasSize(2);
    assertThat(map.get("New")).isNotEqualTo("New");
  }

  @Test
  void mapWithSize() {
    AnnotatedType type = new TypeHolder<@NotNull @WithSize(
        min = 2, max = 3) Map<@NotNull String, @NotNull String>>(){}
                             .annotatedType();
    SerializingMutator<Map<String, String>> mutator =
        (SerializingMutator<Map<String, String>>) FACTORY.createOrThrow(type);
    assertThat(mutator.toString()).isEqualTo("Map<String,String>");

    // Initialize new map with min size
    Map<String, String> map;
    try (MockPseudoRandom prng = mockPseudoRandom(
             // Initial map size
             2,
             // Key 1 size
             4,
             // Key 1 value
             "Key1".getBytes(),
             // Value size
             6,
             // Value value
             "Value1".getBytes(),
             // Key 2 size
             4,
             // Key 2 value
             "Key2".getBytes(),
             // Value size
             6,
             // Value value
             "Value2".getBytes())) {
      map = mutator.init(prng);
    }
    assertThat(map).hasSize(2);
    assertThat(map).containsEntry("Key1", "Value1");
    assertThat(map).containsEntry("Key2", "Value2");

    // Add new entry
    try (MockPseudoRandom prng = mockPseudoRandom(
             // Add new entry
             true,
             // New key size
             3,
             // Key value
             "New".getBytes(),
             // New value size
             3,
             // Value value
             "New".getBytes())) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).hasSize(3);
    assertThat(map).containsEntry("New", "New");

    // Remove one as max size reached
    try (MockPseudoRandom prng = mockPseudoRandom(
             // Add new entry
             true,
             // "Index" to remove
             1)) {
      map = mutator.mutate(map, prng);
    }
    assertThat(map).hasSize(2);
    assertThat(map).containsKey("Key2");
    assertThat(map).containsKey("New");
  }
}
