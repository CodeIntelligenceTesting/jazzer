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

package com.code_intelligence.jazzer.mutation.engine;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.markAsRequiringRecursionBreaking;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.annotatedTypeEquals;
import static java.lang.String.format;
import static java.lang.String.join;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.nCopies;
import static java.util.Collections.unmodifiableList;
import static java.util.function.Function.identity;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.Cache;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeSupport;
import com.code_intelligence.jazzer.utils.Log;
import com.google.errorprone.annotations.CheckReturnValue;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/** A {@link MutatorFactory} that delegates to the given factories in order. */
public final class ChainedMutatorFactory extends ExtendedMutatorFactory {

  private final List<MutatorFactory> fixedFactories;
  private final List<MutatorFactory> prependedFactories;

  private List<String> logs;
  private boolean currentSuppressLog;

  private AnnotatedType innerFailedType;
  private AnnotatedType currentType;
  private int level = -1;

  /**
   * Creates a {@link MutatorFactory} that delegates to the given factories in order.
   *
   * @param cache fuzzing session cache to provide to mutators
   * @param factories a possibly empty collection of factories
   */
  private ChainedMutatorFactory(Cache cache, MutatorFactory... factories) {
    super(cache);
    this.fixedFactories = unmodifiableList(asList(factories));
    this.prependedFactories = new ArrayList<>();
    this.logs = new ArrayList<>();
  }

  @SafeVarargs
  public static ChainedMutatorFactory of(Stream<MutatorFactory>... factories) {
    return of(new IdentityCache(), factories);
  }

  @SafeVarargs
  public static ChainedMutatorFactory of(Cache cache, Stream<MutatorFactory>... factories) {
    return new ChainedMutatorFactory(
        cache, stream(factories).flatMap(identity()).toArray(MutatorFactory[]::new));
  }

  @Override
  @CheckReturnValue
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory parent) {
    AnnotatedType previousType = currentType;
    int currentPrependedFactoriesSize = prependedFactories.size();

    Optional<SerializingMutator<?>> result = Optional.empty();
    currentType = type;
    level++;

    // This is a little hack to get rid of artificial factory invocations caused by the NotNull
    // mutator.
    // It recursively attaches a @NotNull annotation on every reference type and so would log every
    // subtree multiple times.
    boolean previousSuppressPrint = currentSuppressLog;
    currentSuppressLog =
        currentSuppressLog || currentType.getAnnotation(NotNull.class) == TypeSupport.NOT_NULL;

    try {
      // prependedFactories may be modified during the creation of child mutators. Go through an
      // IntStream to allow for this and remove all factories prepended by child mutators before
      // returning from this function.
      result =
          findFirstPresent(
              Stream.concat(
                      IntStream.range(0, currentPrependedFactoriesSize)
                          .mapToObj(prependedFactories::get),
                      fixedFactories.stream())
                  .map(factory -> factory.tryCreate(type, parent)));
      if (!result.isPresent()) {
        if (!currentSuppressLog) {
          String indent = join("", nCopies(level, "    "));
          String typeName = currentType.getType().getTypeName();
          String errorIndicator = innerFailedType == null ? " <<< ERROR" : "";
          logs.add(format("%s%s%s%n", indent, typeName, errorIndicator));
          if (innerFailedType == null) {
            innerFailedType = currentType;
          }
        }
      }
      return result;
    } finally {
      level--;
      currentType = previousType;
      prependedFactories.subList(currentPrependedFactoriesSize, prependedFactories.size()).clear();
      currentSuppressLog = previousSuppressPrint;
      if (level == -1) {
        if (!result.isPresent() && !currentSuppressLog) {
          Collections.reverse(logs);
          String tree = join("", logs);
          String typeName =
              innerFailedType == null
                  ? type.getType().getTypeName()
                  : innerFailedType.getType().getTypeName();
          Log.error(format("Could not find suitable mutator for type: %s%n%s", typeName, tree));
        }
        logs = new ArrayList<>();
      }
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
}
