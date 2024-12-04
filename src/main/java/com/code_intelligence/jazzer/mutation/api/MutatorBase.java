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

/** Provides basic metadata about a mutator. */
public interface MutatorBase {
  /**
   * Whether the type {@code T} mutated by this mutator has a fixed size in memory. This information
   * can be used by mutators for collections of {@code T}s.
   *
   * <p>Examples of types with fixed size include primitive types, enums, and classes with only
   * primitive types and enums as members.
   *
   * <p>Note: Implementing classes should only override this method if the result does not depend on
   * the value of {@code hasFixedSize()} for any child mutators. If it would, instead override
   * {@link SerializingMutator#computeHasFixedSize()} to prevent issues when encountering a cycle.
   */
  boolean hasFixedSize();

  /**
   * Whether the type {@code T} mutated by this mutator is recursive and requires cooperation from
   * its parent mutator to prevent a blow-up of its expected nesting depth.
   *
   * <p>Container types such as lists or optionals should return an empty or minimally sized
   * structure for such element types and themselves return {@code false} from this method.
   *
   * <p>Note: Implementing classes should always return a constant value.
   */
  default boolean requiresRecursionBreaking() {
    return false;
  }
}
