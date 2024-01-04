/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findGettersByPropertyNames;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findGettersByPropertyTypes;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.matchingReturnTypes;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;
import static java.util.Comparator.comparingInt;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.beans.ConstructorProperties;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;

final class ConstructorBasedBeanMutatorFactory implements MutatorFactory {

  // Sort constructors by parameter count descending, then type names.
  private static final Comparator<Constructor<?>> byDescParameterCountAndTypes =
      comparingInt((Constructor<?> c) -> c.getParameterCount())
          .reversed()
          .thenComparing(c -> Arrays.toString(c.getParameterTypes()));

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Object.class)
        // Only concrete classes can be mutated.
        .filter(clazz -> !Modifier.isAbstract(clazz.getModifiers()))
        .flatMap(
            clazz ->
                findFirstPresent(
                    stream(clazz.getDeclaredConstructors())
                        .filter(constructor -> !Modifier.isPrivate(constructor.getModifiers()))
                        // Constructors need parameters, default constructors are handled by the
                        // setter based approach.
                        .filter(constructor -> constructor.getParameterCount() > 0)
                        // If multiple constructors are defined, prefer the one with the most
                        // parameters.
                        .sorted(byDescParameterCountAndTypes)
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
                                          return AggregatesHelper.ofMutable(
                                              factory, constructor, getters);
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
