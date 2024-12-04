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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateIndices;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class EnumMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
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
