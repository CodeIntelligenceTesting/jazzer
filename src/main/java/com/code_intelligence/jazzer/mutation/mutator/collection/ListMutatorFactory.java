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

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.parameterTypeIfParameterized;
import static java.lang.Math.min;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.RandomAccess;
import java.util.function.Predicate;
import java.util.stream.Collectors;

final class ListMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return parameterTypeIfParameterized(type, List.class)
        .flatMap(factory::tryCreate)
        .map(elementMutator
            -> new ListMutator<>(
                elementMutator, ListMutator.DEFAULT_MIN_SIZE, ListMutator.DEFAULT_MAX_SIZE));
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
    }

    @Override
    public List<T> read(DataInputStream in) throws IOException {
      int size = in.readInt();
      ArrayList<T> list = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        list.add(elementMutator.read(in));
      }
      // Wrap in an immutable view for additional protection against accidental mutation in fuzz
      // tests.
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
    public List<T> makeDefaultInstance() {
      // Wrap in an immutable view for additional protection against accidental mutation in fuzz
      // tests.
      return toImmutableListView(new ArrayList<>(maxInitialSize()));
    }

    @Override
    public void initInPlace(List<T> reference, PseudoRandom prng) {
      int targetSize = prng.nextInt(minInitialSize(), maxInitialSize() + 1);
      List<T> list = underlyingMutableList(reference);
      list.clear();
      for (int i = 0; i < targetSize; i++) {
        list.add(elementMutator.init(prng));
      }
    }

    @Override
    public void mutateInPlace(List<T> reference, PseudoRandom prng) {
      List<T> list = underlyingMutableList(reference);
      if (list.isEmpty()) {
        list.add(elementMutator.init(prng));
      } else if (prng.nextInt(4) != 0) {
        int i = prng.nextInt(list.size());
        list.set(i, elementMutator.mutate(list.get(i), prng));
      } else if (list.size() < maxSize) {
        list.add(list.get(list.size() - 1));
      } else if (list.size() > minSize) {
        list.remove(list.size() - 1);
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
        // An immutable list view created by us, so we know how to get back at the mutable list.
        return ((ImmutableListView<T>) value).asMutableList();
      } else {
        // Any kind of list created by someone else (for example using us as a general purpose
        // InPlaceMutator), so assume it is mutable.
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
