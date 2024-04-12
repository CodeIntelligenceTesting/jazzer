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
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.Optional;

final class SetterBasedBeanMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Object.class)
        // Only concrete classes can be mutated.
        .filter(clazz -> !Modifier.isAbstract(clazz.getModifiers()))
        .flatMap(
            clazz -> {
              Constructor<?> constructor;
              try {
                // Find constructors with default visibility by not using getConstructors().
                constructor = clazz.getDeclaredConstructor();
                if (Modifier.isPrivate(constructor.getModifiers())) {
                  return Optional.empty();
                }
              } catch (NoSuchMethodException e) {
                return Optional.empty();
              }

              Method[] setters = getSetters(clazz).toArray(Method[]::new);

              // A Java bean can have additional getters corresponding to computed properties, but
              // we require that all setters have a corresponding getter.
              // TODO: Should we also allow setters without a corresponding getter, as common on
              //  builders? The getters could be replaced with a WeakIdentityHashMap storing the
              //  values passed into the instantiator.
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
