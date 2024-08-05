/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.api;

import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;

import com.google.errorprone.annotations.CheckReturnValue;
import java.lang.reflect.AnnotatedType;
import java.util.List;
import java.util.Optional;

/** A {@link MutatorFactory} that delegates to the given factories in order. */
public final class ChainedMutatorFactory extends MutatorFactory {
  private final List<MutatorFactory> factories;

  /**
   * Creates a {@link MutatorFactory} that delegates to the given factories in order.
   *
   * @param factories a possibly empty collection of factories
   */
  public ChainedMutatorFactory(MutatorFactory... factories) {
    this.factories = unmodifiableList(asList(factories));
  }

  @Override
  @CheckReturnValue
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory parent) {
    return findFirstPresent(factories.stream().map(factory -> factory.tryCreate(type, parent)));
  }
}
