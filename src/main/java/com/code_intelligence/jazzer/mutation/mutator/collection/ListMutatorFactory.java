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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypeIfParameterized;
import static java.lang.Math.min;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.annotation.WithSize;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.MutationAction;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Optional;
import java.util.RandomAccess;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class ListMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    Optional<WithSize> withSize = Optional.ofNullable(type.getAnnotation(WithSize.class));
    int minSize = withSize.map(WithSize::min).orElse(ListMutator.DEFAULT_MIN_SIZE);
    int maxSize = withSize.map(WithSize::max).orElse(ListMutator.DEFAULT_MAX_SIZE);
    return parameterTypeIfParameterized(type, List.class)
        .flatMap(factory::tryCreate)
        .map(elementMutator -> new ListMutator<>(elementMutator, minSize, maxSize));
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
      require(maxSize >= 1, "WithSize#max needs to be greater than 0");
      require(minSize <= maxSize,
          format("WithSize#min %d needs to be smaller or equal than WithSize#max %d", minSize,
              maxSize));
    }

    @Override
    public List<T> read(DataInputStream in) throws IOException {
      int size = RandomSupport.clamp(in.readInt(), minSize, maxSize);
      ArrayList<T> list = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        list.add(elementMutator.read(in));
      }
      // Wrap in an immutable view for additional protection against accidental
      // mutation in fuzz tests.
      return toImmutableListView(list);
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
      // Wrap in an immutable view for additional protection against accidental
      // mutation in fuzz tests.
      return toImmutableListView(new ArrayList<>(maxInitialSize()));
    }

    @Override
    public void initInPlace(List<T> reference, PseudoRandom prng) {
      int targetSize = prng.closedRange(minInitialSize(), maxInitialSize());
      List<T> list = underlyingMutableList(reference);
      list.clear();
      for (int i = 0; i < targetSize; i++) {
        list.add(elementMutator.init(prng));
      }
    }

    private void eraseRandomChunk(List<T> list, PseudoRandom prng, int minSize) {
      int minFinalSize = Math.max(minSize, list.size() / 2);
      int chunkSize;
      if (minFinalSize + 1 == list.size()) {
        chunkSize = 1;
      } else {
        chunkSize = prng.closedRange(1, list.size() - minFinalSize);
      }
      int chunkOffset = prng.closedRange(0, list.size() - chunkSize);
      list.subList(chunkOffset, chunkOffset + chunkSize).clear();
    }

    private void insertRandomChunk(List<T> list, PseudoRandom prng, int maxSize) {
      // Enforces slower growth for smaller lists and lists that are close to
      // `maxSize`.
      int chunkSize = prng.closedRange(1, Math.min(maxSize - list.size(), list.size()));
      int chunkOffset = prng.indexIn(list);
      List<T> tmpAddList = Stream.generate(() -> elementMutator.init(prng))
                               .limit(chunkSize)
                               .collect(Collectors.toList());
      list.addAll(chunkOffset, tmpAddList);
    }

    private void changeRandomChunk(List<T> list, PseudoRandom prng) {
      int chunkOffset = prng.indexIn(list);
      // Muatate at most 10% of the original list
      int chunkSize = Math.min(
          prng.closedRange(1, list.size() - chunkOffset), (int) Math.ceil(list.size() / 10.0));
      ListIterator<T> iterator = list.listIterator(chunkOffset);
      int elementsChanged = 0;
      while (iterator.hasNext() && elementsChanged < chunkSize) {
        T element = iterator.next();
        T mutatedElement = elementMutator.mutate(element, prng);
        iterator.set(mutatedElement);
        elementsChanged++;
      }
    }

    @Override
    public void mutateInPlace(List<T> reference, PseudoRandom prng) {
      List<T> list = underlyingMutableList(reference);
      if (list.isEmpty()) {
        // Early return
        list.add(elementMutator.init(prng));
        return;
      }
      List<MutationAction> actions = MutationAction.getPossibleActions(list, minSize, maxSize);
      switch (actions.get(prng.indexIn(actions))) {
        case SHRINK:
          list.remove(prng.indexIn(list));
          return;
        case SHRINK_CHUNK:
          eraseRandomChunk(list, prng, minSize);
          return;
        case GROW:
          list.add(elementMutator.init(prng));
          return;
        case GROW_CHUNK:
          insertRandomChunk(list, prng, maxSize);
          return;
        case CHANGE:
          int i = prng.indexIn(list);
          list.set(i, elementMutator.mutate(list.get(i), prng));
          return;
        case CHANGE_CHUNK:
          changeRandomChunk(list, prng);
          return;
      }
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
      return min(maxSize, minSize + 1);
    }

    private List<T> underlyingMutableList(List<T> value) {
      if (value instanceof ImmutableListView<?>) {
        // An immutable list view created by us, so we know how to get back at the
        // mutable list.
        return ((ImmutableListView<T>) value).asMutableList();
      } else {
        // Any kind of list created by someone else (for example using us as a general
        // purpose InPlaceMutator), so assume it is mutable.
        return value;
      }
    }

    private List<T> toImmutableListView(List<T> value) {
      if (value instanceof ImmutableListView) {
        return value;
      } else {
        return new ImmutableListView<>(value);
      }
    }
  }

  private static final class ImmutableListView<T> extends AbstractList<T> implements RandomAccess {
    private final List<T> mutableList;

    ImmutableListView(List<T> mutableList) {
      this.mutableList = mutableList;
    }

    List<T> asMutableList() {
      return mutableList;
    }

    @Override
    public T get(int i) {
      return mutableList.get(i);
    }

    @Override
    public int size() {
      return mutableList.size();
    }
  }
}
