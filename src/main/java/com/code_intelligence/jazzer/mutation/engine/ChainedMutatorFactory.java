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
import static java.lang.String.join;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.nCopies;
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
  private static final boolean JAZZER_MUTATOR_DEBUG =
      "1".equals(System.getenv("JAZZER_MUTATOR_DEBUG"));

  private final List<MutatorFactory> fixedFactories;
  private final List<MutatorFactory> prependedFactories;
  private AnnotatedType currentType;
  private int level = -1;

  /**
   * Creates a {@link MutatorFactory} that delegates to the given factories in order.
   *
   * @param factories a possibly empty collection of factories
   */
  public ChainedMutatorFactory(MutatorFactory... factories) {
    this.fixedFactories = unmodifiableList(asList(factories));
    this.prependedFactories = new ArrayList<>();
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
    AnnotatedType previousType = currentType;
    int currentPrependedFactoriesSize = prependedFactories.size();

    currentType = type;
    level++;
    try {
      debugLog("attempt");
      // prependedFactories may be modified during the creation of child mutators. Go through an
      // IntStream to allow for this and remove all factories prepended by child mutators before
      // returning from this function.
      Optional<SerializingMutator<?>> result =
          findFirstPresent(
              Stream.concat(
                      IntStream.range(0, currentPrependedFactoriesSize)
                          .mapToObj(prependedFactories::get),
                      fixedFactories.stream())
                  .map(factory -> factory.tryCreate(type, parent)));
      debugLog(result.isPresent() ? "success" : "failure");
      return result;
    } finally {
      level--;
      currentType = previousType;
      prependedFactories.subList(currentPrependedFactoriesSize, prependedFactories.size()).clear();
    }
  }

  @Override
  public void internMutator(SerializingMutator<?> mutator) {
    AnnotatedType localCurrentType = currentType;
    prependedFactories.add(
        (type, factory) -> {
          if (annotatedTypeEquals(type, localCurrentType)) {
            // A mutator for this aggregate type has already been created, which is the case in
            // particular if it is recursive, i.e., transitively has a field of the same type. We
            // inform the parent mutator to prevent this structure from blowing up, e.g., due to the
            // mutator for nullable types being biased to initialize to a non-null value.
            return Optional.of(markAsRequiringRecursionBreaking(mutator));
          } else {
            return Optional.empty();
          }
        });
  }

  private void debugLog(String status) {
    if (!JAZZER_MUTATOR_DEBUG) {
      return;
    }
    String indent = join("", nCopies(level, "    "));
    System.err.printf("%s%s: %s%n", indent, currentType, status);
  }
}
