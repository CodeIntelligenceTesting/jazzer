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

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

final class ChunkCrossOvers {
  private ChunkCrossOvers() {}

  static <T> void insertChunk(
      List<T> list, List<T> otherList, int maxSize, PseudoRandom prng, boolean hasFixedSize) {
    int maxChunkSize = Math.min(maxSize - list.size(), otherList.size());
    int chunkSize = prng.sizeInClosedRange(1, maxChunkSize, hasFixedSize);
    int fromPos = prng.closedRange(0, otherList.size() - chunkSize);
    int toPos = prng.closedRange(0, list.size());
    List<T> chunk = otherList.subList(fromPos, fromPos + chunkSize);
    list.addAll(toPos, chunk);
  }

  static <T> void overwriteChunk(
      List<T> list, List<T> otherList, PseudoRandom prng, boolean hasFixedSize) {
    onCorrespondingChunks(list, otherList, prng, list::set, hasFixedSize);
  }

  static <T> void crossOverChunk(
      List<T> list, List<T> otherList, SerializingMutator<T> elementMutator, PseudoRandom prng) {
    onCorrespondingChunks(
        list,
        otherList,
        prng,
        (toPos, element) -> {
          list.set(toPos, elementMutator.crossOver(list.get(toPos), element, prng));
        },
        elementMutator.hasFixedSize());
  }

  @FunctionalInterface
  private interface ChunkListElementOperation<T> {
    void apply(int toPos, T chunk);
  }

  private static <T> void onCorrespondingChunks(
      List<T> list,
      List<T> otherList,
      PseudoRandom prng,
      ChunkListElementOperation<T> operation,
      boolean hasFixedSize) {
    int maxChunkSize = Math.min(list.size(), otherList.size());
    int chunkSize = prng.sizeInClosedRange(1, maxChunkSize, hasFixedSize);
    int fromPos = prng.closedRange(0, otherList.size() - chunkSize);
    int toPos = prng.closedRange(0, list.size() - chunkSize);
    List<T> chunk = otherList.subList(fromPos, fromPos + chunkSize);
    for (int i = 0; i < chunk.size(); i++) {
      operation.apply(toPos + i, chunk.get(i));
    }
  }

  static <K, V> void insertChunk(
      Map<K, V> map, Map<K, V> otherMap, int maxSize, PseudoRandom prng, boolean hasFixedSize) {
    int originalSize = map.size();
    int maxChunkSize = Math.min(maxSize - originalSize, otherMap.size());
    int chunkSize = prng.sizeInClosedRange(1, maxChunkSize, hasFixedSize);
    int fromChunkOffset = prng.closedRange(0, otherMap.size() - chunkSize);
    Iterator<Entry<K, V>> fromIterator = otherMap.entrySet().iterator();
    for (int i = 0; i < fromChunkOffset; i++) {
      fromIterator.next();
    }
    // insertChunk only inserts new entries and does not overwrite existing
    // ones. As skipping those entries would lead to fewer insertions than
    // requested, loop over the rest of the map to fill the chunk if possible.
    while (map.size() < originalSize + chunkSize && fromIterator.hasNext()) {
      Entry<K, V> entry = fromIterator.next();
      if (!map.containsKey(entry.getKey())) {
        map.put(entry.getKey(), entry.getValue());
      }
    }
  }

  static <K, V> void overwriteChunk(
      Map<K, V> map, Map<K, V> otherMap, PseudoRandom prng, boolean hasFixedSize) {
    onCorrespondingChunks(
        map,
        otherMap,
        prng,
        (fromIterator, toIterator, chunkSize) -> {
          // As keys can not be overwritten, only removed and new ones added, this
          // cross over overwrites the values. Removal of keys is handled by the
          // removeChunk mutation. Value equality is not checked here.
          for (int i = 0; i < chunkSize; i++) {
            Entry<K, V> from = fromIterator.next();
            Entry<K, V> to = toIterator.next();
            to.setValue(from.getValue());
          }
        },
        hasFixedSize);
  }

  static <K, V> void crossOverChunk(
      Map<K, V> map,
      Map<K, V> otherMap,
      SerializingMutator<K> keyMutator,
      SerializingMutator<V> valueMutator,
      PseudoRandom prng) {
    if (prng.choice()) {
      crossOverChunkKeys(map, otherMap, keyMutator, prng);
    } else {
      crossOverChunkValues(map, otherMap, valueMutator, prng);
    }
  }

  private static <K, V> void crossOverChunkKeys(
      Map<K, V> map, Map<K, V> otherMap, SerializingMutator<K> keyMutator, PseudoRandom prng) {
    onCorrespondingChunks(
        map,
        otherMap,
        prng,
        (fromIterator, toIterator, chunkSize) -> {
          Map<K, V> entriesToAdd = new LinkedHashMap<>(chunkSize);
          for (int i = 0; i < chunkSize; i++) {
            Entry<K, V> to = toIterator.next();
            Entry<K, V> from = fromIterator.next();

            // The entry has to be removed from the map before the cross-over, as
            // mutating its key could cause problems in subsequent lookups.
            // Furthermore, no new entries may be added while using the iterator,
            // so crossed-over keys are collected for later addition.
            K key = to.getKey();
            V value = to.getValue();
            toIterator.remove();

            // As cross-overs do not guarantee to mutate the given object, no
            // checks if the crossed over key already exists in the map are
            // performed. This potentially overwrites existing entries or
            // generates equal keys.
            // In case of cross over this behavior is acceptable.
            K newKey = keyMutator.crossOver(key, from.getKey(), prng);

            // Prevent null keys, as those are not allowed in some map implementations.
            if (newKey != null) {
              entriesToAdd.put(newKey, value);
            }
          }
          map.putAll(entriesToAdd);
        },
        keyMutator.hasFixedSize());
  }

  private static <K, V> void crossOverChunkValues(
      Map<K, V> map, Map<K, V> otherMap, SerializingMutator<V> valueMutator, PseudoRandom prng) {
    // As cross-overs do not guarantee to mutate the given object, no
    // checks if a new value is produced are performed.
    // The cross-over could have already mutated value, but explicitly set it
    // through the iterator to be sure.
    onCorrespondingChunks(
        map,
        otherMap,
        prng,
        (fromIterator, toIterator, chunkSize) -> {
          for (int i = 0; i < chunkSize; i++) {
            Entry<K, V> fromEntry = fromIterator.next();
            Entry<K, V> toEntry = toIterator.next();
            // As cross-overs do not guarantee to mutate the given object, no
            // checks if a new value is produced are performed.
            V newValue = valueMutator.crossOver(toEntry.getValue(), fromEntry.getValue(), prng);

            // The cross-over could have already mutated value, but explicitly set it
            // through the iterator to be sure.
            toEntry.setValue(newValue);
          }
        },
        valueMutator.hasFixedSize());
  }

  @FunctionalInterface
  private interface ChunkMapOperation<K, V> {
    void apply(Iterator<Entry<K, V>> fromIterator, Iterator<Entry<K, V>> toIterator, int chunkSize);
  }

  static <K, V> void onCorrespondingChunks(
      Map<K, V> map,
      Map<K, V> otherMap,
      PseudoRandom prng,
      ChunkMapOperation<K, V> operation,
      boolean hasFixedSize) {
    int maxChunkSize = Math.min(map.size(), otherMap.size());
    int chunkSize = prng.sizeInClosedRange(1, maxChunkSize, hasFixedSize);
    int fromChunkOffset = prng.closedRange(0, otherMap.size() - chunkSize);
    int toChunkOffset = prng.closedRange(0, map.size() - chunkSize);
    Iterator<Entry<K, V>> fromIterator = otherMap.entrySet().iterator();
    for (int i = 0; i < fromChunkOffset; i++) {
      fromIterator.next();
    }
    Iterator<Entry<K, V>> toIterator = map.entrySet().iterator();
    for (int i = 0; i < toChunkOffset; i++) {
      toIterator.next();
    }
    operation.apply(fromIterator, toIterator, chunkSize);
  }

  public enum CrossOverAction {
    INSERT_CHUNK,
    OVERWRITE_CHUNK,
    CROSS_OVER_CHUNK,
    NOOP;

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
        return NOOP; // prevent NPE
      }
      return prng.pickIn(actions);
    }
  }
}
