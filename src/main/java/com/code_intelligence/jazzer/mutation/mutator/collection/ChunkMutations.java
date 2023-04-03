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

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

// Based on (Apache-2.0)
// https://github.com/google/fuzztest/blob/f81257ed70ec7b9c191b633588cb6e39c42da5e4/fuzztest/internal/domains/container_mutation_helpers.h
final class ChunkMutations {
  private ChunkMutations() {}

  static <T> void deleteRandomChunk(List<T> list, int minSize, PseudoRandom prng) {
    int oldSize = list.size();
    Preconditions.require(oldSize > minSize);

    int minFinalSize = Math.max(minSize, oldSize / 2);
    int chunkSize = prng.closedRangeBiasedTowardsSmall(1, oldSize - minFinalSize);
    int chunkOffset = prng.closedRange(0, oldSize - chunkSize);

    list.subList(chunkOffset, chunkOffset + chunkSize).clear();
  }

  static <T> void insertRandomChunk(
      List<T> list, int maxSize, SerializingMutator<T> elementMutator, PseudoRandom prng) {
    int oldSize = list.size();
    Preconditions.require(oldSize < maxSize);

    int chunkSize = prng.closedRangeBiasedTowardsSmall(1, maxSize - oldSize);
    int chunkOffset = prng.closedRange(0, oldSize);

    T baseElement = elementMutator.init(prng);
    T[] chunk = (T[]) new Object[chunkSize];
    for (int i = 0; i < chunk.length; i++) {
      chunk[i] = elementMutator.detach(baseElement);
    }
    // ArrayList#addAll relies on Collection#toArray, but Arrays#asList returns a List whose
    // toArray() always makes a copy. We avoid this by using a custom list implementation.
    list.addAll(chunkOffset, new ArraySharingList<>(chunk));
  }

  static <T> void mutateRandomChunk(
      List<T> list, SerializingMutator<T> mutator, PseudoRandom prng) {
    int oldSize = list.size();
    int chunkSize = prng.closedRangeBiasedTowardsSmall(1, oldSize);
    int chunkOffset = prng.closedRange(0, oldSize - chunkSize);

    for (int i = chunkOffset; i < chunkOffset + chunkSize; i++) {
      list.set(i, mutator.mutate(list.get(i), prng));
    }
  }

  public enum MutationAction {
    DELETE_CHUNK,
    INSERT_CHUNK,
    MUTATE_CHUNK;

    public static MutationAction pickRandomAction(
        Collection<?> c, int minSize, int maxSize, PseudoRandom prng) {
      List<MutationAction> actions = new ArrayList<>();
      if (c.size() > minSize) {
        actions.add(DELETE_CHUNK);
      }
      if (c.size() < maxSize) {
        actions.add(INSERT_CHUNK);
      }
      if (!c.isEmpty()) {
        actions.add(MUTATE_CHUNK);
      }
      return prng.pickIn(actions);
    }
  }

  private static final class ArraySharingList<T> extends AbstractList<T> {
    private final T[] array;

    ArraySharingList(T[] array) {
      this.array = array;
    }

    @Override
    public T get(int i) {
      return array[i];
    }

    @Override
    public int size() {
      return array.length;
    }

    @Override
    public Object[] toArray() {
      return array;
    }
  }
}
