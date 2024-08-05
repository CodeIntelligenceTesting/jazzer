/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateIndices;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class EnumMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return asSubclassOrEmpty(type, Enum.class)
        .map(
            parent -> {
              require(
                  ((Class<Enum<?>>) type.getType()).getEnumConstants().length > 1,
                  String.format(
                      "%s defines less than two enum constants and can't be mutated. Use a constant"
                          + " instead.",
                      parent));
              Enum<?>[] values = ((Class<Enum<?>>) type.getType()).getEnumConstants();
              return mutateThenMap(
                  mutateIndices(values.length),
                  (index) -> values[index],
                  Enum::ordinal,
                  (Predicate<Debuggable> inCycle) -> "Enum<" + parent.getSimpleName() + ">");
            });
  }
}
