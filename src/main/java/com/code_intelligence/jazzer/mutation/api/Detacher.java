/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.api;

import com.google.errorprone.annotations.CheckReturnValue;

/** Knows how to clone a {@code T} such that it shares no mutable state with the original. */
@FunctionalInterface
public interface Detacher<T> {
  /**
   * Returns an equal instance that shares no mutable state with {@code value}.
   *
   * <p>Implementations
   *
   * <ul>
   *   <li>MUST return an instance that {@link Object#equals(Object)} the argument;
   *   <li>MUST return an instance that cannot be used to mutate the state of the argument through
   *       its API (ignoring uses of {@link sun.misc.Unsafe});
   *   <li>MUST return an instance that is not affected by any changes to the original value made by
   *       any mutator;
   *   <li>MUST be accepted by mutator methods just like the original value;
   *   <li>MAY return the argument itself if it is deeply immutable.
   * </ul>
   *
   * @param value the instance to detach
   * @return an equal instance that shares no mutable state with {@code value}
   */
  @CheckReturnValue
  T detach(T value);
}
