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
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import java.util.AbstractList;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

// Based on (Apache-2.0)
// https://github.com/google/fuzztest/blob/f81257ed70ec7b9c191b633588cb6e39c42da5e4/fuzztest/internal/domains/container_mutation_helpers.h
@SuppressWarnings("unchecked")
final class ChunkMutations {
  private static final int MAX_FAILED_INSERTION_ATTEMPTS = 100;

  private ChunkMutations() {}

  static <T> void deleteRandomChunk(
      List<T> list, int minSize, PseudoRandom prng, boolean hasFixedSize) {
    int oldSize = list.size();
    int minFinalSize = Math.max(minSize, oldSize / 2);
    int chunkSize = prng.sizeInClosedRange(1, oldSize - minFinalSize, hasFixedSize);
    int chunkOffset = prng.closedRange(0, oldSize - chunkSize);

    list.subList(chunkOffset, chunkOffset + chunkSize).clear();
  }

  static <T> void deleteRandomChunk(
      Collection<T> collection, int minSize, PseudoRandom prng, boolean hasFixedSize) {
    int oldSize = collection.size();
    int minFinalSize = Math.max(minSize, oldSize / 2);
    int chunkSize = prng.sizeInClosedRange(1, oldSize - minFinalSize, hasFixedSize);
    int chunkOffset = prng.closedRange(0, oldSize - chunkSize);

    Iterator<T> it = collection.iterator();
    for (int i = 0; i < chunkOffset; i++) {
      it.next();
    }
    for (int i = chunkOffset; i < chunkOffset + chunkSize; i++) {
      it.next();
      it.remove();
    }
  }

  static <T> void insertRandomChunk(
      List<T> list, int maxSize, SerializingMutator<T> elementMutator, PseudoRandom prng) {
    int oldSize = list.size();
    int chunkSize = prng.sizeInClosedRange(1, maxSize - oldSize, elementMutator.hasFixedSize());
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

  static <T> boolean insertRandomChunk(
      Set<T> set,
      Consumer<T> addIfNew,
      int maxSize,
      ValueMutator<T> elementMutator,
      PseudoRandom prng) {
    int oldSize = set.size();
    int chunkSize = prng.sizeInClosedRange(1, maxSize - oldSize, elementMutator.hasFixedSize());
    return growBy(set, addIfNew, chunkSize, () -> elementMutator.init(prng));
  }

  static <T> void mutateRandomChunk(List<T> list, ValueMutator<T> mutator, PseudoRandom prng) {
    int size = list.size();
    int chunkSize = prng.sizeInClosedRange(1, size, mutator.hasFixedSize());
    int chunkOffset = prng.closedRange(0, size - chunkSize);

    for (int i = chunkOffset; i < chunkOffset + chunkSize; i++) {
      list.set(i, mutator.mutate(list.get(i), prng));
    }
  }

  static <T> void mutateRandomAt(List<T> list, ValueMutator<T> mutator, PseudoRandom prng) {
    int index = prng.indexIn(list.size());
    list.set(index, mutator.mutate(list.get(index), prng));
  }

  static <K, V, KW, VW> boolean mutateRandomKeysChunk(
      Map<K, V> map, SerializingMutator<K> keyMutator, PseudoRandom prng) {
    int originalSize = map.size();
    int chunkSize = prng.sizeInClosedRange(1, originalSize, keyMutator.hasFixedSize());
    int chunkOffset = prng.closedRange(0, originalSize - chunkSize);

    // To ensure that mutating keys actually results in the set of keys changing and not just their
    // values (which is what #mutateRandomValuesChunk is for), we keep the keys to mutate in the
    // map, try to add new keys (that are therefore distinct from the keys to mutate) and only
    // remove the successfully mutated keys in the end.
    ArrayDeque<KW> keysToMutate = new ArrayDeque<>(chunkSize);
    ArrayDeque<VW> values = new ArrayDeque<>(chunkSize);
    ArrayList<K> keysToRemove = new ArrayList<>(chunkSize);
    Iterator<Map.Entry<K, V>> it = map.entrySet().iterator();
    for (int i = 0; i < chunkOffset; i++) {
      it.next();
    }
    for (int i = chunkOffset; i < chunkOffset + chunkSize; i++) {
      Map.Entry<K, V> entry = it.next();
      // ArrayDeque cannot hold null elements, which requires us to replace null with a sentinel.
      // Also detach the key as keys may be mutable and mutation could destroy them.
      keysToMutate.add(boxNull(keyMutator.detach(entry.getKey())));
      values.add(boxNull(entry.getValue()));
      keysToRemove.add(entry.getKey());
    }

    Consumer<K> addIfNew =
        key -> {
          int sizeBeforeAdd = map.size();
          map.putIfAbsent(key, unboxNull(values.peekFirst()));
          // The mutated key was new, try to mutate and add the next in line.
          if (map.size() > sizeBeforeAdd) {
            keysToMutate.removeFirst();
            values.removeFirst();
          }
        };
    Supplier<K> nextCandidate =
        () -> {
          // Mutate the next candidate in the queue.
          K candidate = keyMutator.mutate(unboxNull(keysToMutate.removeFirst()), prng);
          keysToMutate.addFirst(boxNull(candidate));
          return candidate;
        };

    growBy(map.keySet(), addIfNew, chunkSize, nextCandidate);
    // Remove the original keys that were successfully mutated into new keys. Since the original
    // keys have been kept in the map up to this point, all keys added were successfully mutated to
    // be unequal to the original keys.
    int grownBy = map.size() - originalSize;
    keysToRemove.stream().limit(grownBy).forEach(map::remove);
    return grownBy > 0;
  }

  public static <K, V> void mutateRandomValuesChunk(
      Map<K, V> map, ValueMutator<V> valueMutator, PseudoRandom prng) {
    Collection<Map.Entry<K, V>> collection = map.entrySet();
    int oldSize = collection.size();
    int chunkSize = prng.sizeInClosedRange(1, oldSize, valueMutator.hasFixedSize());
    int chunkOffset = prng.closedRange(0, oldSize - chunkSize);

    Iterator<Map.Entry<K, V>> it = collection.iterator();
    for (int i = 0; i < chunkOffset; i++) {
      it.next();
    }
    for (int i = chunkOffset; i < chunkOffset + chunkSize; i++) {
      Entry<K, V> entry = it.next();
      entry.setValue(valueMutator.mutate(entry.getValue(), prng));
    }
  }

  static <T> boolean growBy(
      Set<T> set, Consumer<T> addIfNew, int delta, Supplier<T> candidateSupplier) {
    int oldSize = set.size();
    Preconditions.require(delta >= 0);

    final int targetSize = oldSize + delta;
    int remainingAttempts = MAX_FAILED_INSERTION_ATTEMPTS;
    int currentSize = set.size();
    while (currentSize < targetSize) {
      // If addIfNew fails, the size of set will not increase.
      addIfNew.accept(candidateSupplier.get());
      int newSize = set.size();
      if (newSize == currentSize && remainingAttempts-- == 0) {
        return false;
      } else {
        currentSize = newSize;
      }
    }
    return true;
  }

  private static final Object BOXED_NULL = new Object();

  private static <T, TW> TW boxNull(T object) {
    return object != null ? (TW) object : (TW) BOXED_NULL;
  }

  private static <T, TW> T unboxNull(TW object) {
    return object != BOXED_NULL ? (T) object : null;
  }

  public enum MutationAction {
    DELETE_CHUNK,
    INSERT_CHUNK,
    MUTATE_CHUNK;

    public static MutationAction pickRandomMutationAction(
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
