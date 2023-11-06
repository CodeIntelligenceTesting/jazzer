/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.engine;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.markAsRequiringRecursionBreaking;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.annotatedTypeEquals;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.unmodifiableList;
import static java.util.function.Function.identity;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.google.errorprone.annotations.CheckReturnValue;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/** A {@link MutatorFactory} that delegates to the given factories in order. */
public final class ChainedMutatorFactory extends ExtendedMutatorFactory {
  private final List<MutatorFactory> fixedFactories;

  /**
   * Creates a {@link MutatorFactory} that delegates to the given factories in order.
   *
   * @param factories a possibly empty collection of factories
   */
  public ChainedMutatorFactory(MutatorFactory... factories) {
    this.fixedFactories = unmodifiableList(asList(factories));
  }

  @SafeVarargs
  public static ChainedMutatorFactory of(Stream<MutatorFactory>... factories) {
    return new ChainedMutatorFactory(
        stream(factories).flatMap(identity()).toArray(MutatorFactory[]::new));
  }

  @Override
  @CheckReturnValue
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory parent) {
      return findFirstPresent(fixedFactories.stream()
              .map(factory -> factory.tryCreate(type, parent)));
  }
}
