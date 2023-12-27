/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory.FailedToConstructChildMutatorException;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import com.google.errorprone.annotations.ImmutableTypeParameter;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Optional;

final class AggregatesHelper {

  @SuppressWarnings("Immutable")
  public static Optional<SerializingMutator<?>> ofImmutable(
      ExtendedMutatorFactory factory, Executable instantiator, Method... getters) {
    Preconditions.check(
        getters.length == instantiator.getParameterCount(),
        String.format(
            "Number of getters (%d) does not match number of parameters of %s",
            getters.length, instantiator));
    for (int i = 0; i < getters.length; i++) {
      Preconditions.check(
          getters[i]
              .getAnnotatedReturnType()
              .getType()
              .equals(instantiator.getAnnotatedParameterTypes()[i].getType()),
          String.format(
              "Parameter %d of %s does not match return type of %s", i, instantiator, getters[i]));
    }

    // TODO: Ideally, we would have the mutator framework pass in a Lookup for the fuzz test class.
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    return ofImmutableChecked(
            factory,
            unreflectNewInstance(lookup, instantiator),
            instantiator.getAnnotatedParameterTypes(),
            instantiator.getDeclaringClass(),
            unreflectMethods(lookup, getters))
        .map(m -> (SerializingMutator<?>) m);
  }

  private static <@ImmutableTypeParameter T> Optional<SerializingMutator<T>> ofImmutableChecked(
      ExtendedMutatorFactory factory,
      MethodHandle instantiator,
      AnnotatedType[] instantiatorParameterTypes,
      Class<?> instantiatedClass,
      MethodHandle... getters) {
    try {
      return Optional.of(
          mutateThenMapToImmutable(
              () ->
                  ((Optional<SerializingMutator<?>[]>)
                          toArrayOrEmpty(
                              stream(instantiatorParameterTypes).map(factory::tryCreate),
                              SerializingMutator[]::new))
                      .map(MutatorCombinators::mutateProduct)
                      .orElseThrow(FailedToConstructChildMutatorException::new),
              components -> {
                try {
                  return (T) instantiator.invokeWithArguments(components);
                } catch (Throwable e) {
                  throw new RuntimeException(e);
                }
              },
              object -> {
                Object[] objects = new Object[getters.length];
                for (int i = 0; i < getters.length; i++) {
                  try {
                    objects[i] = getters[i].invoke(object);
                  } catch (Throwable e) {
                    throw new RuntimeException(e);
                  }
                }
                return objects;
              },
              (productMutator, inCycle) ->
                  productMutator.toDebugString(inCycle)
                      + " -> "
                      + instantiatedClass.getSimpleName(),
              factory::internMutator));
    } catch (FailedToConstructChildMutatorException e) {
      return Optional.empty();
    }
  }

  private static MethodHandle unreflectNewInstance(
      MethodHandles.Lookup lookup, Executable newInstance) {
    Preconditions.check(
        newInstance instanceof Constructor || Modifier.isStatic(newInstance.getModifiers()),
        String.format(
            "New instance method %s must be a static method or a constructor", newInstance));
    Preconditions.check(
        newInstance.getAnnotatedReturnType().getType() != Void.class,
        String.format("Return type of %s must not be void", newInstance));
    newInstance.setAccessible(true);
    try {
      if (newInstance instanceof Method) {
        return lookup.unreflect((Method) newInstance);
      } else {
        return lookup.unreflectConstructor((Constructor<?>) newInstance);
      }
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }

  private static MethodHandle[] unreflectMethods(MethodHandles.Lookup lookup, Method... methods) {
    return stream(methods)
        .map(
            method -> {
              method.setAccessible(true);
              try {
                return lookup.unreflect(method);
              } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
              }
            })
        .toArray(MethodHandle[]::new);
  }

  private AggregatesHelper() {}
}
