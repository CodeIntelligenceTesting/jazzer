/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregatesHelper.buildProductMutatorForParameters;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregatesHelper.unreflectNewInstance;
import static com.code_intelligence.jazzer.mutation.mutator.aggregate.BeanSupport.findConstructorsByParameterCount;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.findFirstPresent;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.suppliedOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

final class CachedConstructorMutatorFactory implements MutatorFactory {

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Object.class)
        .flatMap(
            clazz ->
                findFirstPresent(
                    findConstructorsByParameterCount(clazz).stream()
                        .map(
                            constructor ->
                                suppliedOrEmpty(() -> buildMutator(constructor, type, factory)))));
  }

  private static SerializingMutator<Object> buildMutator(
      Constructor<?> constructor, AnnotatedType type, ExtendedMutatorFactory factory) {
    MethodHandle instantiator = unreflectNewInstance(MethodHandles.lookup(), constructor);

    Supplier<SerializingMutator<Object[]>> parametersMutator =
        () ->
            buildProductMutatorForParameters(
                type, constructor.getAnnotatedParameterTypes(), factory);

    Function<Object[], Object> fromParametersToObject =
        parameters -> {
          Object instance = instantiate(instantiator, parameters);
          factory.getCache().put(instance, parameters);
          return instance;
        };

    Function<Object, Object[]> fromObjectToParameters =
        instance -> factory.getCache().get(instance);

    BiFunction<SerializingMutator<Object[]>, Predicate<Debuggable>, String> debug =
        (productMutator, inCycle) ->
            productMutator.toDebugString(inCycle)
                + " -> "
                + constructor.getDeclaringClass().getSimpleName();

    return mutateThenMap(
        parametersMutator,
        fromParametersToObject,
        fromObjectToParameters,
        debug,
        factory::internMutator);
  }

  private static Object instantiate(MethodHandle constructor, Object[] parameters) {
    try {
      return constructor.invokeWithArguments(parameters);
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }
}
