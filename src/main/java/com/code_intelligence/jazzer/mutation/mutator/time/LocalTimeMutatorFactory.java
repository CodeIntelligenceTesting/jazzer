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
