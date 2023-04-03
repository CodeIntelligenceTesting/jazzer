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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockInitializer;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockMutator;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ChunkMutationsTest {
  @Test
  void testDeleteRandomChunk() {
    List<Integer> list = Stream.of(1, 2, 3, 4, 5, 6).collect(toList());

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      ChunkMutations.deleteRandomChunk(list, 2, prng);
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
  void testMutateChunk() {
    List<Integer> list = Stream.of(1, 2, 3, 4, 5, 6).collect(toList());

    try (MockPseudoRandom prng = mockPseudoRandom(2, 3)) {
      ChunkMutations.mutateRandomChunk(list, mockMutator(1, i -> 2 * i), prng);
    }
    assertThat(list).containsExactly(1, 2, 3, 8, 10, 6).inOrder();
  }
}
