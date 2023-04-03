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

package com.code_intelligence.jazzer.mutation.api;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static java.lang.String.format;

import com.google.errorprone.annotations.CheckReturnValue;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;

/**
 * Instances of this class are not required to be thread safe, but are generally lightweight and can
 * thus be created as needed.
 */
public abstract class MutatorFactory {
  public final boolean canMutate(AnnotatedType type) {
    return tryCreate(type).isPresent();
  }

  public final <T> SerializingMutator<T> createOrThrow(Class<T> clazz) {
    return (SerializingMutator<T>) createOrThrow(asAnnotatedType(clazz));
  }

  public final SerializingMutator<?> createOrThrow(AnnotatedType type) {
    Optional<SerializingMutator<?>> maybeMutator = tryCreate(type);
    require(maybeMutator.isPresent(), "Failed to create mutator for " + type);
    return maybeMutator.get();
  }

  public final SerializingInPlaceMutator<?> createInPlaceOrThrow(AnnotatedType type) {
    Optional<SerializingInPlaceMutator<?>> maybeMutator = tryCreateInPlace(type);
    require(maybeMutator.isPresent(), "Failed to create mutator for " + type);
    return maybeMutator.get();
  }

  /**
   * Tries to create a mutator for {@code type} and, if successful, asserts that it is an instance
   * of {@link SerializingInPlaceMutator}.
   */
  public final Optional<SerializingInPlaceMutator<?>> tryCreateInPlace(AnnotatedType type) {
    return tryCreate(type).map(mutator -> {
      require(mutator instanceof InPlaceMutator<?>,
          format("Mutator for %s is not in-place: %s", type, mutator.getClass()));
      return (SerializingInPlaceMutator<?>) mutator;
    });
  }

  @CheckReturnValue
  public final Optional<SerializingMutator<?>> tryCreate(AnnotatedType type) {
    return tryCreate(type, this);
  }

  /**
   * Attempt to create a {@link SerializingMutator} for the given type.
   *
   * @param type the type to mutate
   * @param factory the factory to use when creating submutators
   * @return a {@link SerializingMutator} for the given {@code type}, or {@link Optional#empty()}
   * if this factory can't create such mutators
   */
  @CheckReturnValue
  public abstract Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, MutatorFactory factory);
}
