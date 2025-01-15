/*
 * Copyright 2025 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators;
import com.code_intelligence.jazzer.mutation.support.TypeSupport;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.ToIntFunction;

final class SealedClassMutatorFactory<T> implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    if (!(type.getType() instanceof Class<?>)) {
      return Optional.empty();
    }
    Class<T>[] permittedSubclasses =
        (Class<T>[]) ((Class<T>) type.getType()).getPermittedSubclasses();
    if (permittedSubclasses == null) {
      return Optional.empty();
    }

    ToIntFunction<T> getState =
        (value) -> {
          // We can't use value.getClass() as it might be a subclass of the permitted (direct)
          // subclasses.
          for (int i = 0; i < permittedSubclasses.length; i++) {
            if (permittedSubclasses[i].isInstance(value)) {
              return i;
            }
          }
          return -1;
        };
    return toArrayOrEmpty(
            stream(permittedSubclasses)
                .map(TypeSupport::asAnnotatedType)
                .map(TypeSupport::notNull)
                .map(factory::tryCreate),
            SerializingMutator<?>[]::new)
        .map(
            mutators -> MutatorCombinators.mutateSum(getState, (SerializingMutator<T>[]) mutators));
  }
}
