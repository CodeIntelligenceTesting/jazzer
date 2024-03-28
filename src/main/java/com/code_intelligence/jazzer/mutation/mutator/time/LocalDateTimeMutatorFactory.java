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
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.TimeZone;
import java.util.function.Predicate;

@SuppressWarnings("unchecked")
final class LocalDateTimeMutatorFactory implements MutatorFactory {

  private static final AnnotatedType INNER_LONG_TYPE =
      notNull(
          new TypeHolder<
              // min, max stolen from java.time.Instant.MIN_SECONDS, java.time.Instant.MAX_SECONDS
              @InRange(min = -31557014167219200L, max = 31556889864403199L)
              Long>() {}.annotatedType());

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {

    return asSubclassOrEmpty(type, LocalDateTime.class)
        .flatMap(parent -> factory.tryCreate(INNER_LONG_TYPE))
        .map(
            longMutator ->
                mutateThenMap(
                    (SerializingMutator<Long>) longMutator,
                    LocalDateTimeMutatorFactory::toLocalDateTime,
                    LocalDateTimeMutatorFactory::fromLocalDateTime,
                    (Predicate<Debuggable> inCycle) -> "LocalDateTime"));
  }

  public static LocalDateTime toLocalDateTime(long timestamp) {
    return LocalDateTime.ofInstant(
        Instant.ofEpochMilli(timestamp), TimeZone.getDefault().toZoneId());
  }

  public static long fromLocalDateTime(LocalDateTime localDateTime) {
    return localDateTime.atZone(TimeZone.getDefault().toZoneId()).toInstant().toEpochMilli();
  }
}
