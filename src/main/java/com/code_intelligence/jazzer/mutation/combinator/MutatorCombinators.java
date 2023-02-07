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

import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import java.util.Arrays;
import java.util.function.BiConsumer;
import java.util.function.Function;
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
      public String toString() {
        Class<?> owningType =
            TypeResolver.resolveRawArguments(Function.class, getter.getClass())[0];
        return owningType.getSimpleName() + "." + mutator;
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
      public String toString() {
        Class<?> owningType = TypeResolver.resolveRawArguments(Function.class, map.getClass())[0];
        return owningType.getSimpleName() + " via " + mutator;
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
      public String toString() {
        return stream(mutators).map(Object::toString).collect(joining(", ", "{", "}"));
      }
    };
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
}
