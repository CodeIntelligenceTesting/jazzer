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
import java.lang.reflect.AnnotatedType;
import java.util.Optional;

/**
 * Instances of this class are not required to be thread safe, but are generally lightweight and can
 * thus be created as needed.
 */
public interface MutatorFactory {

  /**
   * Attempt to create a {@link SerializingMutator} for the given type.
   *
   * @param type the type to mutate
   * @param factory the factory to use when creating submutators
   * @return a {@link SerializingMutator} for the given {@code type}, or {@link Optional#empty()} if
   *     this factory can't create such mutators
   */
  @CheckReturnValue
  Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, ExtendedMutatorFactory factory);

  /**
   * This exception can be thrown in mutator constructors to indicate that they failed to construct
   * a child mutator. This should be treated by callers as the equivalent of returning {@link
   * Optional#empty()} from {@link #tryCreate(AnnotatedType, ExtendedMutatorFactory)}, which may not
   * be possible in mutator factories for recursive structures that need to create child mutators in
   * a mutators constructor.
   */
  final class FailedToConstructChildMutatorException extends RuntimeException {
    public FailedToConstructChildMutatorException() {
      super("Failed to construct a mutator");
    }
  }
}
