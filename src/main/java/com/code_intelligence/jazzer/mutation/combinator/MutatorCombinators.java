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

package com.code_intelligence.jazzer.mutation.combinator;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.requireNonNullElements;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import net.jodah.typetools.TypeResolver;

public final class MutatorCombinators {
  private MutatorCombinators() {}

  public static <T, R> InPlaceMutator<T> mutateProperty(
      Function<T, R> getter, ValueMutator<R> mutator, BiConsumer<T, R> setter) {
    requireNonNull(getter);
    requireNonNull(mutator);
    requireNonNull(setter);
    return new InPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        setter.accept(reference, mutator.init(prng));
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        setter.accept(reference, mutator.mutate(getter.apply(reference), prng));
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        Class<?> owningType =
            TypeResolver.resolveRawArguments(Function.class, getter.getClass())[0];
        return owningType.getSimpleName() + "." + mutator.toDebugString(isInCycle);
      }

      @Override
      public String toString() {
        return Debuggable.getDebugString(this);
      }
    };
  }

  public static <T, R> InPlaceMutator<T> mutateViaView(
      Function<T, R> map, InPlaceMutator<R> mutator) {
    requireNonNull(map);
    requireNonNull(mutator);
    return new InPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        mutator.initInPlace(map.apply(reference), prng);
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        mutator.mutateInPlace(map.apply(reference), prng);
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        Class<?> owningType = TypeResolver.resolveRawArguments(Function.class, map.getClass())[0];
        return owningType.getSimpleName() + " via " + mutator.toDebugString(isInCycle);
      }

      @Override
      public String toString() {
        return Debuggable.getDebugString(this);
      }
    };
  }

  /**
   * Combines multiple in-place mutators for different parts of a {@code T} into one that picks one
   * at random whenever it mutates.
   */
  @SafeVarargs
  public static <T> InPlaceMutator<T> combine(InPlaceMutator<T>... partialMutators) {
    requireNonNullElements(partialMutators);
    require(partialMutators.length > 0, "mutators must not be empty");
    return new InPlaceMutator<T>() {
      private final InPlaceMutator<T>[] mutators =
          Arrays.copyOf(partialMutators, partialMutators.length);

      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        for (InPlaceMutator<T> mutator : mutators) {
          mutator.initInPlace(reference, prng);
        }
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        mutators[prng.nextInt(mutators.length)].mutateInPlace(reference, prng);
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return stream(mutators)
            .map(mutator -> mutator.toDebugString(isInCycle))
            .collect(joining(", ", "{", "}"));
      }

      @Override
      public String toString() {
        return Debuggable.getDebugString(this);
      }
    };
  }

  /**
   * Assembles the parameters into a full implementation of {@link SerializingInPlaceMutator<T>}:
   *
   * @param registerSelf        a callback that will receive the uninitialized mutator instance
   *                            before {@code lazyMutator} is invoked. For simple cases this can
   *                            just do nothing, but it is needed to implement mutators for
   *                            structures that are self-referential (e.g. Protobuf message A having
   *                            a field of type A).
   * @param makeDefaultInstance constructs a mutable default instance of {@code T}
   * @param serializer          implementation of the {@link Serializer<T>} part
   * @param lazyMutator         supplies the implementation of the {@link InPlaceMutator<T>} part.
   *                            This is guaranteed to be invoked exactly once and only after
   *                            {@code registerSelf}.
   */
  public static <T> SerializingInPlaceMutator<T> assemble(
      Consumer<SerializingInPlaceMutator<T>> registerSelf, Supplier<T> makeDefaultInstance,
      Serializer<T> serializer, Supplier<InPlaceMutator<T>> lazyMutator) {
    return new DelegatingSerializingInPlaceMutator<>(
        registerSelf, makeDefaultInstance, serializer, lazyMutator);
  }

  public static <T, R> SerializingMutator<R> mutateThenMap(
      SerializingMutator<T> mutator, Function<T, R> map, Function<R, T> inverse) {
    return new PostComposedMutator<T, R>(mutator, map, inverse) {};
  }

  public static <T, R> SerializingMutator<R> mutateThenMapToImmutable(
      SerializingMutator<T> mutator, Function<T, R> map, Function<R, T> inverse) {
    return new PostComposedMutator<T, R>(mutator, map, inverse) {
      @Override
      public R detach(R value) {
        return value;
      }
    };
  }

  /**
   * Combines multiple mutators for potentially different types into one that mutates an
   * {@code Object[]} containing one instance per mutator.
   */
  public static ProductMutator mutateProduct(SerializingMutator... mutators) {
    return new ProductMutator(mutators);
  }

  private static class DelegatingSerializingInPlaceMutator<T> extends SerializingInPlaceMutator<T> {
    private final Supplier<T> makeDefaultInstance;
    private final Serializer<T> serializer;
    private final InPlaceMutator<T> mutator;

    private DelegatingSerializingInPlaceMutator(Consumer<SerializingInPlaceMutator<T>> registerSelf,
        Supplier<T> makeDefaultInstance, Serializer<T> serializer,
        Supplier<InPlaceMutator<T>> lazyMutator) {
      requireNonNull(makeDefaultInstance);
      requireNonNull(serializer);

      registerSelf.accept(this);
      this.makeDefaultInstance = makeDefaultInstance;
      this.serializer = serializer;
      this.mutator = lazyMutator.get();
    }

    @Override
    public void initInPlace(T reference, PseudoRandom prng) {
      mutator.initInPlace(reference, prng);
    }

    @Override
    public void mutateInPlace(T reference, PseudoRandom prng) {
      mutator.mutateInPlace(reference, prng);
    }

    @Override
    protected T makeDefaultInstance() {
      return makeDefaultInstance.get();
    }

    @Override
    public T read(DataInputStream in) throws IOException {
      return serializer.read(in);
    }

    @Override
    public void write(T value, DataOutputStream out) throws IOException {
      serializer.write(value, out);
    }

    @Override
    public T readExclusive(InputStream in) throws IOException {
      return serializer.readExclusive(in);
    }

    @Override
    public void writeExclusive(T value, OutputStream out) throws IOException {
      serializer.writeExclusive(value, out);
    }

    @Override
    public T detach(T value) {
      return serializer.detach(value);
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      if (isInCycle.test(this)) {
        return "(cycle)";
      } else {
        return mutator.toDebugString(isInCycle);
      }
    }
  }
}
