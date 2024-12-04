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

import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.*;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Optional;

final class SetterBasedBeanMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Object.class)
        .filter(BeanSupport::isConcreteClass)
        .flatMap(BeanSupport::findDefaultConstructor)
        .flatMap(
            constructor -> {
              Class<?> clazz = constructor.getDeclaringClass();
              Method[] setters = findMethods(clazz, BeanSupport::isSetter).toArray(Method[]::new);

              // Classes with a default constructor but without setters are handled by the
              // CachedConstructorMutator.
              if (setters.length == 0) {
                return Optional.empty();
              }

              // A Java bean can have additional getters corresponding to computed properties, but
              // we require that all setters have a corresponding getter.
              return findGettersByPropertyNames(
                      clazz, stream(setters).map(BeanSupport::toPropertyName))
                  .filter(
                      getters ->
                          matchingReturnTypes(
                              getters,
                              stream(setters)
                                  .map(setter -> setter.getAnnotatedParameterTypes()[0].getType())
                                  .toArray(Type[]::new)))
                  .flatMap(
                      getters ->
                          AggregatesHelper.createMutator(
                              factory, type, constructor, getters, setters));
            });
  }
}
