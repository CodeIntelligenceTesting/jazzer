/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.time;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;

import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.lang.reflect.AnnotatedType;
import java.time.LocalTime;
import java.util.Optional;
import java.util.function.Predicate;

@SuppressWarnings("unchecked")
final class LocalTimeMutatorFactory implements MutatorFactory {

  private static final AnnotatedType INNER_LONG_TYPE =
      notNull(
          new TypeHolder<
              // min, max stolen from java.time.temporal.ChronoField.SECOND_OF_DAY
              @InRange(min = 0, max = 86400L - 1) Long>() {}.annotatedType());

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {

    return asSubclassOrEmpty(type, LocalTime.class)
        .flatMap(parent -> factory.tryCreate(INNER_LONG_TYPE))
        .map(
            longMutator ->
                mutateThenMap(
                    (SerializingMutator<Long>) longMutator,
                    LocalTimeMutatorFactory::toLocalTime,
                    LocalTimeMutatorFactory::fromLocalTime,
                    (Predicate<Debuggable> inCycle) -> "LocalTime"));
  }

  public static LocalTime toLocalTime(long secondsOfDay) {
    return LocalTime.ofSecondOfDay(secondsOfDay);
  }

  public static long fromLocalTime(LocalTime localTime) {
    return localTime.toSecondOfDay();
  }
}
