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
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.insertRandomChunk;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.mutateRandomAt;
import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.mutateRandomChunk;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypeIfParameterized;
import static java.lang.Math.min;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

final class ListMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return parameterTypeIfParameterized(type, List.class)
        .map(innerType -> propagatePropertyConstraints(type, innerType))
        .flatMap(factory::tryCreate)
        .map(
            elementMutator -> {
              Optional<WithSize> withSize = Optional.ofNullable(type.getAnnotation(WithSize.class));
              int minSize = withSize.map(WithSize::min).orElse(ListMutator.DEFAULT_MIN_SIZE);
              int maxSize = withSize.map(WithSize::max).orElse(ListMutator.DEFAULT_MAX_SIZE);
              return new ListMutator<>(elementMutator, minSize, maxSize);
            });
  }

  private static final class ListMutator<T> extends SerializingInPlaceMutator<List<T>> {
    private static final int DEFAULT_MIN_SIZE = 0;
    private static final int DEFAULT_MAX_SIZE = 1000;

    private final SerializingMutator<T> elementMutator;
    private final int minSize;
    private final int maxSize;

    ListMutator(SerializingMutator<T> elementMutator, int minSize, int maxSize) {
      this.elementMutator = elementMutator;
      this.minSize = minSize;
      this.maxSize = maxSize;
      require(maxSize >= 1, format("WithSize#max=%d needs to be greater than 0", maxSize));
      require(minSize >= 0, format("WithSize#min=%d needs to be positive", minSize));
      require(
          minSize <= maxSize,
          format(
              "WithSize#min=%d needs to be smaller or equal than WithSize#max=%d",
              minSize, maxSize));
    }

    @Override
    public List<T> read(DataInputStream in) throws IOException {
      int size = RandomSupport.clamp(in.readInt(), minSize, maxSize);
      ArrayList<T> list = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        list.add(elementMutator.read(in));
      }
      return list;
    }

    @Override
    public void write(List<T> list, DataOutputStream out) throws IOException {
      out.writeInt(list.size());
      for (T element : list) {
        elementMutator.write(element, out);
      }
    }

    @Override
    protected List<T> makeDefaultInstance() {
      return new ArrayList<>(maxInitialSize());
    }

    @Override
    public void initInPlace(List<T> list, PseudoRandom prng) {
      int targetSize = prng.closedRange(minInitialSize(), maxInitialSize());
      list.clear();
      for (int i = 0; i < targetSize; i++) {
        list.add(elementMutator.init(prng));
      }
    }

    @Override
    public void mutateInPlace(List<T> list, PseudoRandom prng) {
      switch (pickRandomMutationAction(list, minSize, maxSize, prng)) {
        case DELETE_CHUNK:
          deleteRandomChunk(list, minSize, prng, elementMutator.hasFixedSize());
          break;
        case INSERT_CHUNK:
          insertRandomChunk(list, maxSize, elementMutator, prng);
          break;
        case MUTATE_CHUNK:
          // Prioritize mutating a single element over a chunk mutation 70% of the time.
          if (prng.indexIn(10) < 7) {
            mutateRandomAt(list, elementMutator, prng);
          } else {
            mutateRandomChunk(list, elementMutator, prng);
          }
          break;
        default:
          throw new IllegalStateException("unsupported action");
      }
    }

    @Override
    public void crossOverInPlace(List<T> reference, List<T> otherReference, PseudoRandom prng) {
      // These cross-over functions don't remove entries, that is handled by
      // the appropriate mutations on the result.
      switch (pickRandomCrossOverAction(reference, otherReference, maxSize, prng)) {
        case INSERT_CHUNK:
          insertChunk(reference, otherReference, maxSize, prng, elementMutator.hasFixedSize());
          break;
        case OVERWRITE_CHUNK:
          overwriteChunk(reference, otherReference, prng, elementMutator.hasFixedSize());
          break;
        case CROSS_OVER_CHUNK:
          crossOverChunk(reference, otherReference, elementMutator, prng);
          break;
        default:
          // Both lists are empty or could otherwise not be crossed over.
      }
    }

    @Override
    public boolean hasFixedSize() {
      return false;
    }

    @Override
    public List<T> detach(List<T> value) {
      return value.stream()
          .map(elementMutator::detach)
          .collect(Collectors.toCollection(() -> new ArrayList<>(value.size())));
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "List<" + elementMutator.toDebugString(isInCycle) + ">";
    }

    private int minInitialSize() {
      return minSize;
    }

    private int maxInitialSize() {
      if (elementMutator.requiresRecursionBreaking()) {
        return minInitialSize();
      }
      return min(maxSize, minSize + 1);
    }
  }
}
