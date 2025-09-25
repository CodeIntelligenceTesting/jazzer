/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypesIfParameterized;
import static java.lang.Math.min;
import static java.lang.String.format;
import static java.util.stream.Collectors.toSet;

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
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

final class SetMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return parameterTypesIfParameterized(type, Set.class)
        .map(
            parameterTypes ->
                parameterTypes.stream()
                    .map(innerType -> propagatePropertyConstraints(type, innerType))
                    .map(factory::tryCreate)
                    .flatMap(StreamSupport::getOrEmpty)
                    .collect(Collectors.toList()))
        .filter(elementMutator -> elementMutator.size() == 1)
        .map(
            elementMutator -> {
              int min = SetMutator.DEFAULT_MIN_SIZE;
              int max = SetMutator.DEFAULT_MAX_SIZE;
              for (Annotation annotation : type.getDeclaredAnnotations()) {
                if (annotation instanceof WithSize) {
                  WithSize withSize = (WithSize) annotation;
                  min = withSize.min();
                  max = withSize.max();
                }
              }

              return new SetMutator<>(elementMutator.get(0), min, max);
            });
  }

  private static final class SetMutator<K> extends SerializingInPlaceMutator<Set<K>> {
    private static final int DEFAULT_MIN_SIZE = 0;
    private static final int DEFAULT_MAX_SIZE = 1000;

    private final SerializingMutator<K> keyMutator;
    private final int minSize;
    private final int maxSize;

    SetMutator(SerializingMutator<K> keyMutator, int minSize, int maxSize) {
      this.keyMutator = keyMutator;
      this.minSize = minSize;
      this.maxSize = maxSize;

      require(maxSize >= 1, format("WithSize#max=%d needs to be greater than 0", maxSize));
      // TODO: Add support for min > 0 to set. If min > 0, then #read can fail to construct
      //       sufficiently many distinct keys, but the mutation framework currently doesn't offer
      //       a way to handle this situation gracefully. It is also not clear what behavior users
      //       could reasonably expect in this situation in both regression test and fuzzing mode.
      require(minSize == 0, "@WithSize#min != 0 is not yet supported for Set");
    }

    @Override
    public Set<K> read(DataInputStream in) throws IOException {
      int size = RandomSupport.clamp(in.readInt(), minSize, maxSize);
      Set<K> set = new LinkedHashSet<>(size);
      for (int i = 0; i < size; i++) {
        set.add(keyMutator.read(in));
      }
      // set may have less than size entries due to the potential for duplicates, but this is fine
      // as we currently assert that minSize == 0.
      return set;
    }

    @Override
    public void write(Set<K> set, DataOutputStream out) throws IOException {
      out.writeInt(set.size());
      for (K entry : set) {
        keyMutator.write(entry, out);
      }
    }

    @Override
    protected Set<K> makeDefaultInstance() {
      return new LinkedHashSet<>(maxInitialSize());
    }

    @Override
    public void initInPlace(Set<K> set, PseudoRandom prng) {
      int targetSize = prng.closedRange(minInitialSize(), maxInitialSize());
      set.clear();
      growBy(set, set::add, targetSize, () -> keyMutator.init(prng));
      if (set.size() < minSize) {
        throw new IllegalStateException(
            String.format(
                "Failed to create %d distinct elements of type %s to satisfy the @WithSize#minSize"
                    + " constraint on Set",
                minSize, keyMutator));
      }
    }

    @Override
    public void mutateInPlace(Set<K> set, PseudoRandom prng) {
      switch (pickRandomMutationAction(set, minSize, maxSize, prng)) {
        case DELETE_CHUNK:
          deleteRandomChunk(set, minSize, prng, entriesHaveFixedSize());
          break;
        case INSERT_CHUNK:
          insertRandomChunk(set, set::add, maxSize, keyMutator, prng);
          break;
        case MUTATE_CHUNK:
          ChunkMutations.mutateRandomChunk(set, keyMutator, prng);
          break;
        default:
          throw new IllegalStateException("unsupported action");
      }
    }

    @Override
    public void crossOverInPlace(Set<K> reference, Set<K> otherReference, PseudoRandom prng) {
      switch (pickRandomCrossOverAction(reference, otherReference, maxSize, prng)) {
        case INSERT_CHUNK:
          insertChunk(reference, otherReference, maxSize, prng, entriesHaveFixedSize());
          break;
        case OVERWRITE_CHUNK:
          overwriteChunk(reference, otherReference, prng, entriesHaveFixedSize());
          break;
        case CROSS_OVER_CHUNK:
          crossOverChunk(reference, otherReference, keyMutator, prng);
          break;
        default:
          // Both sets are empty or could otherwise not be crossed over.
      }
    }

    private boolean entriesHaveFixedSize() {
      return keyMutator.hasFixedSize();
    }

    @Override
    public boolean hasFixedSize() {
      return false;
    }

    @Override
    public Set<K> detach(Set<K> value) {
      return value.stream().map(keyMutator::detach).collect(toSet());
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Set<" + keyMutator.toDebugString(isInCycle) + ">";
    }

    private int minInitialSize() {
      return minSize;
    }

    private int maxInitialSize() {
      if (keyMutator.requiresRecursionBreaking()) {
        return minInitialSize();
      }
      return min(maxSize, minSize + 1);
    }
  }
}
