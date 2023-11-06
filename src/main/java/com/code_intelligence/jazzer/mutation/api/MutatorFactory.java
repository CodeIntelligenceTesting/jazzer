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
