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

import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findConstructorsByParameterCount;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findGettersByPropertyNames;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findGettersByPropertyTypes;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.matchingReturnTypes;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.beans.ConstructorProperties;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Optional;

final class ConstructorBasedBeanMutatorFactory implements MutatorFactory {

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Object.class)
        .filter(BeanSupport::isConcreteClass)
        .flatMap(
            clazz ->
                findFirstPresent(
                    findConstructorsByParameterCount(clazz)
                        // Classes with only a default constructor are handled by the
                        // CashedConstructorMutatorFactory.
                        .filter(constructor -> constructor.getParameterCount() > 0)
                        .map(
                            constructor ->
                                findParameterGetters(clazz, constructor)
                                    .filter(
                                        getters ->
                                            matchingReturnTypes(
                                                getters, constructor.getParameterTypes()))
                                    .flatMap(
                                        getters -> {
                                          // Try to create mutator based on constructor and getters,
                                          // if not all parameters are supported by the mutation
                                          // framework, empty is returned.
                                          return AggregatesHelper.createMutator(
                                              factory, type, constructor, getters, false);
                                        }))));
  }

  private Optional<Method[]> findParameterGetters(Class<?> clazz, Constructor<?> constructor) {
    // Prefer explicit Java Bean ConstructorProperties annotation to determine parameter names.
    ConstructorProperties parameterNames = constructor.getAnnotation(ConstructorProperties.class);
    if (parameterNames != null
        && parameterNames.value().length == constructor.getParameterCount()) {
      return findGettersByPropertyNames(clazz, stream(parameterNames.value()));
    }
    Parameter[] parameters = constructor.getParameters(); // parameter size is guaranteed to be > 0
    if (parameters[0].isNamePresent()) {
      // Fallback to parameter names, if available.
      return findGettersByPropertyNames(clazz, stream(parameters).map(Parameter::getName));
    } else {
      // Last fallback to parameter types.
      return findGettersByPropertyTypes(clazz, stream(parameters).map(Parameter::getType));
    }
  }
}
