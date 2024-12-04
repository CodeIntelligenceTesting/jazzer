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

import static java.util.Collections.newSetFromMap;
import static java.util.Objects.requireNonNull;

import java.util.IdentityHashMap;
import java.util.Set;
import java.util.function.Predicate;

public interface Debuggable {
  /**
   * Returns a string representation of the object that is meant to be used to make assertions about
   * its structure in tests.
   *
   * @param isInCycle evaluates to {@code true} if a cycle has been detected during recursive calls
   *     of this function. Must be called at most once with {@code this} as the single argument.
   *     Implementing classes that know that their current instance can never be contained in
   *     recursive substructures need not call this method.
   */
  String toDebugString(Predicate<Debuggable> isInCycle);

  /**
   * Returns a string representation of the given {@link Debuggable} that is meant to be used to
   * make assertions about its structure in tests.
   */
  static String getDebugString(Debuggable debuggable) {
    Set<Debuggable> seen = newSetFromMap(new IdentityHashMap<>());
    return debuggable.toDebugString(child -> !seen.add(requireNonNull(child)));
  }
}
