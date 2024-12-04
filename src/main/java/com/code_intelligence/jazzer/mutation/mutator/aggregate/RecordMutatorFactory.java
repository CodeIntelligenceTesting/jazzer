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

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Optional;

final class RecordMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Record.class)
        .flatMap(
            clazz -> {
              try {
                return AggregatesHelper.createMutator(
                    factory,
                    type,
                    getCanonicalConstructor(clazz),
                    stream(clazz.getRecordComponents())
                        .map(RecordComponent::getAccessor)
                        .toArray(Method[]::new),
                    true);
              } catch (NoSuchMethodException e) {
                throw new IllegalStateException(e);
              }
            });
  }

  private <T extends Record> Constructor<T> getCanonicalConstructor(Class<T> clazz)
      throws NoSuchMethodException {
    Class<?>[] paramTypes =
        stream(clazz.getRecordComponents()).map(RecordComponent::getType).toArray(Class<?>[]::new);
    return clazz.getDeclaredConstructor(paramTypes);
  }
}
