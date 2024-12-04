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

import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkCrossOvers.CrossOverAction.pickRandomCrossOverAction;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkCrossOvers.crossOverChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkCrossOvers.insertChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkCrossOvers.overwriteChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.MutationAction.pickRandomMutationAction;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.deleteRandomChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.growBy;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.insertRandomChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.mutateRandomKeysChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.mutateRandomValuesChunk;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypesIfParameterized;
import static java.lang.Math.min;
import static java.lang.String.format;
import static java.util.stream.Collectors.toMap;

import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import com.code_intelligence.jazzer.mutation.support.StreamSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

final class MapMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return parameterTypesIfParameterized(type, Map.class)
        .map(
            parameterTypes ->
                parameterTypes.stream()
                    .map(innerType -> propagatePropertyConstraints(type, innerType))
                    .map(factory::tryCreate)
                    .flatMap(StreamSupport::getOrEmpty)
                    .collect(Collectors.toList()))
        .filter(elementMutators -> elementMutators.size() == 2)
        .map(
            elementMutators -> {
              int min = MapMutator.DEFAULT_MIN_SIZE;
              int max = MapMutator.DEFAULT_MAX_SIZE;
              for (Annotation annotation : type.getDeclaredAnnotations()) {
                if (annotation instanceof WithSize) {
                  WithSize withSize = (WithSize) annotation;
                  min = withSize.min();
                  max = withSize.max();
                }
              }
              return new MapMutator<>(elementMutators.get(0), elementMutators.get(1), min, max);
            });
  }

  private static final class MapMutator<K, V> extends SerializingInPlaceMutator<Map<K, V>> {
    private static final int DEFAULT_MIN_SIZE = 0;
    private static final int DEFAULT_MAX_SIZE = 1000;

    private final SerializingMutator<K> keyMutator;
    private final SerializingMutator<V> valueMutator;
    private final int minSize;
    private final int maxSize;

    MapMutator(
        SerializingMutator<K> keyMutator,
        SerializingMutator<V> valueMutator,
        int minSize,
        int maxSize) {
      this.keyMutator = keyMutator;
      this.valueMutator = valueMutator;
      this.minSize = Math.max(minSize, DEFAULT_MIN_SIZE);
      this.maxSize = Math.min(maxSize, DEFAULT_MAX_SIZE);

      require(maxSize >= 1, format("WithSize#max=%d needs to be greater than 0", maxSize));
      // TODO: Add support for min > 0 to map. If min > 0, then #read can fail to construct
      //       sufficiently many distinct keys, but the mutation framework currently doesn't offer
      //       a way to handle this situation gracefully. It is also not clear what behavior users
      //       could reasonably expect in this situation in both regression test and fuzzing mode.
      require(minSize == 0, "@WithSize#min != 0 is not yet supported for Map");
    }

    @Override
    public Map<K, V> read(DataInputStream in) throws IOException {
      int size = RandomSupport.clamp(in.readInt(), minSize, maxSize);
      Map<K, V> map = new LinkedHashMap<>(size);
      for (int i = 0; i < size; i++) {
        map.put(keyMutator.read(in), valueMutator.read(in));
      }
      // map may have less than size entries due to the potential for duplicates, but this is fine
      // as we currently assert that minSize == 0.
      return map;
    }

    @Override
    public void write(Map<K, V> map, DataOutputStream out) throws IOException {
      out.writeInt(map.size());
      for (Map.Entry<K, V> entry : map.entrySet()) {
        keyMutator.write(entry.getKey(), out);
        valueMutator.write(entry.getValue(), out);
      }
    }

    @Override
    protected Map<K, V> makeDefaultInstance() {
      // Use a LinkedHashMap to ensure deterministic iteration order, which makes chunk-based
      // mutations deterministic. The additional overhead compared to HashMap should be minimal.
      return new LinkedHashMap<>(maxInitialSize());
    }

    @Override
    public void initInPlace(Map<K, V> map, PseudoRandom prng) {
      int targetSize = prng.closedRange(minInitialSize(), maxInitialSize());
      map.clear();
      growBy(
          map.keySet(),
          key -> map.putIfAbsent(key, valueMutator.init(prng)),
          targetSize,
          () -> keyMutator.init(prng));
      if (map.size() < minSize) {
        throw new IllegalStateException(
            String.format(
                "Failed to create %d distinct elements of type %s to satisfy the @WithSize#minSize"
                    + " constraint on Map",
                minSize, keyMutator));
      }
    }

    @Override
    public void mutateInPlace(Map<K, V> map, PseudoRandom prng) {
      switch (pickRandomMutationAction(map.keySet(), minSize, maxSize, prng)) {
        case DELETE_CHUNK:
          deleteRandomChunk(map.keySet(), minSize, prng, entriesHaveFixedSize());
          break;
        case INSERT_CHUNK:
          insertRandomChunk(
              map.keySet(),
              key -> map.putIfAbsent(key, valueMutator.init(prng)),
              maxSize,
              keyMutator,
              prng);
          break;
        case MUTATE_CHUNK:
          if (prng.choice() || !mutateRandomKeysChunk(map, keyMutator, prng)) {
            mutateRandomValuesChunk(map, valueMutator, prng);
          }
          break;
        default:
          throw new IllegalStateException("unsupported action");
      }
    }

    @Override
    public void crossOverInPlace(Map<K, V> reference, Map<K, V> otherReference, PseudoRandom prng) {
      switch (pickRandomCrossOverAction(
          reference.keySet(), otherReference.keySet(), maxSize, prng)) {
        case INSERT_CHUNK:
          insertChunk(reference, otherReference, maxSize, prng, entriesHaveFixedSize());
          break;
        case OVERWRITE_CHUNK:
          overwriteChunk(reference, otherReference, prng, entriesHaveFixedSize());
          break;
        case CROSS_OVER_CHUNK:
          crossOverChunk(reference, otherReference, keyMutator, valueMutator, prng);
          break;
        default:
          // Both maps are empty or could otherwise not be crossed over.
      }
    }

    private boolean entriesHaveFixedSize() {
      return keyMutator.hasFixedSize() && valueMutator.hasFixedSize();
    }

    @Override
    public boolean hasFixedSize() {
      return false;
    }

    @Override
    public Map<K, V> detach(Map<K, V> value) {
      return value.entrySet().stream()
          .collect(
              toMap(
                  entry -> keyMutator.detach(entry.getKey()),
                  entry -> valueMutator.detach(entry.getValue())));
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Map<"
          + keyMutator.toDebugString(isInCycle)
          + ", "
          + valueMutator.toDebugString(isInCycle)
          + ">";
    }

    private int minInitialSize() {
      return minSize;
    }

    private int maxInitialSize() {
      if (keyMutator.requiresRecursionBreaking() || valueMutator.requiresRecursionBreaking()) {
        return minInitialSize();
      }
      return min(maxSize, minSize + 1);
    }
  }
}
