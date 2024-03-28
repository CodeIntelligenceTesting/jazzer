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
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@SuppressWarnings("unchecked")
final class ZonedDateTimeMutatorFactory implements MutatorFactory {

  private static final List<ZoneId> AVAILABLE_ZONE_IDS =
      ZoneId.getAvailableZoneIds().stream().map(ZoneId::of).collect(Collectors.toList());

  private static final AnnotatedType INNER_LONG_TYPE =
      notNull(
          new TypeHolder<
              // min, max stolen from java.time.Instant.MIN_SECONDS, java.time.Instant.MAX_SECONDS
              @InRange(min = -31557014167219200L, max = 31556889864403199L)
              Long>() {}.annotatedType());

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {

    return asSubclassOrEmpty(type, ZonedDateTime.class)
        .flatMap(parent -> factory.tryCreate(INNER_LONG_TYPE))
        .map(
            longMutator ->
                mutateThenMap(
                    (SerializingMutator<Long>) longMutator,
                    ZonedDateTimeMutatorFactory::toZonedDateTime,
                    ZonedDateTimeMutatorFactory::fromZonedDateTime,
                    (Predicate<Debuggable> inCycle) -> "ZonedDateTime"));
  }

  public static ZonedDateTime toZonedDateTime(long timestamp) {
    ZoneId zoneId = AVAILABLE_ZONE_IDS.get(Math.abs((int) (timestamp % AVAILABLE_ZONE_IDS.size())));
    return ZonedDateTime.ofInstant(Instant.ofEpochMilli(timestamp), zoneId);
  }

  public static long fromZonedDateTime(ZonedDateTime zonedDateTime) {
    return zonedDateTime.toInstant().toEpochMilli();
  }
}
