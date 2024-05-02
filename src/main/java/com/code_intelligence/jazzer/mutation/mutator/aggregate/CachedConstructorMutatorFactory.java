/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregatesHelper.asInstantiationFunction;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findConstructorsByParameterCount;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.util.Optional;
import java.util.function.Function;

final class CachedConstructorMutatorFactory implements MutatorFactory {

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Object.class)
        .filter(BeanSupport::isConcreteClass)
        .flatMap(
            clazz ->
                findFirstPresent(
                    findConstructorsByParameterCount(clazz)
                        .map(constructor -> buildMutator(constructor, type, factory))));
  }

  private static Optional<SerializingMutator<?>> buildMutator(
      Constructor<?> constructor, AnnotatedType initialType, ExtendedMutatorFactory factory) {

    Function<Object[], Object> instantiator =
        asInstantiationFunction(MethodHandles.lookup(), constructor);

    Function<Object[], Object> fromParametersToObject =
        parameters -> {
          Object instance = instantiator.apply(parameters);
          factory.getCache().put(instance, parameters);
          return instance;
        };

    Function<Object, Object[]> fromObjectToParameters =
        instance -> factory.getCache().get(instance);

    return AggregatesHelper.createMutator(
        factory,
        constructor.getDeclaringClass(),
        constructor.getAnnotatedParameterTypes(),
        fromParametersToObject,
        fromObjectToParameters,
        initialType,
        false);
  }
}
