/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
                          AggregatesHelper.ofMutable(factory, type, constructor, getters, setters));
            });
  }
}
