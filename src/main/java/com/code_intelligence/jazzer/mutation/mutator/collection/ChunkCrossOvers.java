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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

final class ChunkCrossOvers {
  private ChunkCrossOvers() {}

  static <T> void insertChunk(List<T> list, List<T> otherList, int maxSize, PseudoRandom prng) {
    int maxChunkSize = Math.min(maxSize - list.size(), Math.min(list.size(), otherList.size()));
    withChunk(list, otherList, maxChunkSize, prng,
        (fromPos, toPos, chunk) -> { list.addAll(toPos, chunk); });
  }

  static <T> void overwriteChunk(List<T> list, List<T> otherList, PseudoRandom prng) {
    int maxChunkSize = Math.min(list.size(), otherList.size());
    withChunkElements(list, otherList, maxChunkSize, prng, list::set);
  }

  static <T> void crossOverChunk(
      List<T> list, List<T> otherList, SerializingMutator<T> elementMutator, PseudoRandom prng) {
    int maxChunkSize = Math.min(list.size(), otherList.size());
    withChunkElements(list, otherList, maxChunkSize, prng, (toPos, element) -> {
      list.set(toPos, elementMutator.crossOver(list.get(toPos), element, prng));
    });
  }

  @FunctionalInterface
  private interface ChunkListOperation<T> {
    void apply(int fromPos, int toPos, List<T> chunk);
  }

  @FunctionalInterface
  private interface ChunkListElementOperation<T> {
    void apply(int toPos, T chunk);
  }

  static private <T> void withChunk(List<T> list, List<T> otherList, int maxChunkSize,
      PseudoRandom prng, ChunkListOperation<T> operation) {
    if (maxChunkSize == 0) {
      return;
    }
    int chunkSize = prng.closedRangeBiasedTowardsSmall(1, maxChunkSize);
    int fromPos = prng.closedRange(0, otherList.size() - chunkSize);
    int toPos = prng.closedRange(0, list.size() - chunkSize);
    List<T> chunk = otherList.subList(fromPos, fromPos + chunkSize);
    operation.apply(fromPos, toPos, chunk);
  }

  static private <T> void withChunkElements(List<T> list, List<T> otherList, int maxChunkSize,
      PseudoRandom prng, ChunkListElementOperation<T> operation) {
    withChunk(list, otherList, maxChunkSize, prng, (fromPos, toPos, chunk) -> {
      for (int i = 0; i < chunk.size(); i++) {
        operation.apply(toPos + i, chunk.get(i));
      }
    });
  }

  public enum CrossOverAction {
    INSERT_CHUNK,
    OVERWRITE_CHUNK,
    CROSS_OVER_CHUNK,
    NOOP_CHUNK;

    public static CrossOverAction pickRandomCrossOverAction(
        Collection<?> reference, Collection<?> otherReference, int maxSize, PseudoRandom prng) {
      List<CrossOverAction> actions = new ArrayList<>();
      if (reference.size() < maxSize && !otherReference.isEmpty()) {
        actions.add(INSERT_CHUNK);
      }
      if (!reference.isEmpty() && !otherReference.isEmpty()) {
        actions.add(OVERWRITE_CHUNK);
        actions.add(CROSS_OVER_CHUNK);
      }
      if (actions.isEmpty()) {
        return NOOP_CHUNK; // prevent NPE
      }
      return prng.pickIn(actions);
    }
  }
}
