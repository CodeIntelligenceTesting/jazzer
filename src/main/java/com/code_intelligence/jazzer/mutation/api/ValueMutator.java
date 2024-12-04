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

package com.code_intelligence.jazzer.mutation.api;

import com.google.errorprone.annotations.CheckReturnValue;

/**
 * Knows how to initialize and mutate objects of type {@code T} and how to incorporate (cross over)
 * parts of another object of the same type.
 *
 * <p>Certain types can be mutated fully in place. In such cases, prefer implementing the more
 * versatile {@link InPlaceMutator} instead.
 *
 * <p>Implementations
 *
 * <ul>
 *   <li>MAY weakly associate mutable state with the identity (not equality class) of objects they
 *       have been passed as arguments or returned from initialization functions;
 *   <li>MAY assume that they are only passed arguments that they have initialized or mutated;
 *   <li>SHOULD use {@link com.code_intelligence.jazzer.mutation.support.WeakIdentityHashMap} for
 *       this purpose;
 *   <li>MUST otherwise be deeply immutable;
 *   <li>SHOULD override {@link Object#toString()} to return {@code
 *       Debuggable.getDebugString(this)}.
 * </ul>
 *
 * @param <T> the type this mutator operates on
 */
public interface ValueMutator<T> extends Debuggable, MutatorBase {

  /**
   * Implementations
   *
   * <ul>
   *   <li>SHOULD, when called repeatedly, return a low amount of duplicates.
   * </ul>
   *
   * @return an instance of {@code T}
   */
  @CheckReturnValue
  T init(PseudoRandom prng);

  /**
   * Implementations
   *
   * <ul>
   *   <li>MUST return a value that does not {@link Object#equals(Object)} the argument (if
   *       possible);
   *   <li>SHOULD, when called repeatedly, be able to eventually return any valid value of type
   *       {@code T};
   *   <li>MAY mutate the argument.
   * </ul>
   */
  @CheckReturnValue
  T mutate(T value, PseudoRandom prng);

  /**
   * Implementations
   *
   * <ul>
   *   <li>MUST return a value that does not {@link Object#equals(Object)} the arguments (if
   *       possible);
   *   <li>MAY mutate {@code value}.
   *   <li>MUST NOT mutate {@code otherValue}.
   * </ul>
   */
  @CheckReturnValue
  T crossOver(T value, T otherValue, PseudoRandom prng);
}
