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
