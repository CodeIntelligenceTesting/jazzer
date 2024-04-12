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
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory.FailedToConstructChildMutatorException;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

final class AggregatesHelper {

  public static Optional<SerializingMutator<?>> ofImmutable(
      ExtendedMutatorFactory factory,
      AnnotatedType initialType,
      Executable instantiator,
      Method... getters) {
    return createConstructorBasedMutator(factory, initialType, instantiator, getters, true);
  }

  public static Optional<SerializingMutator<?>> ofMutable(
      ExtendedMutatorFactory factory,
      AnnotatedType initialType,
      Executable instantiator,
      Method... getters) {
    return createConstructorBasedMutator(factory, initialType, instantiator, getters, false);
  }

  private static Optional<SerializingMutator<?>> createConstructorBasedMutator(
      ExtendedMutatorFactory factory,
      AnnotatedType initialType,
      Executable instantiator,
      Method[] getters,
      boolean isImmutable) {
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
    return createChecked(
            factory,
            initialType,
            components -> {
              try {
                return unreflectNewInstance(lookup, instantiator).invokeWithArguments(components);
              } catch (Throwable e) {
                throw new RuntimeException(e);
              }
            },
            instantiator.getAnnotatedParameterTypes(),
            instantiator.getDeclaringClass(),
            isImmutable,
            unreflectMethods(lookup, getters))
        .map(m -> m);
  }

  public static Optional<SerializingMutator<?>> ofMutable(
      ExtendedMutatorFactory factory,
      AnnotatedType initialType,
      Executable newInstance,
      Method[] getters,
      Method[] setters) {
    Preconditions.check(
        getters.length == setters.length,
        String.format(
            "Number of getters (%d) does not match number of setters (%d)",
            getters.length, setters.length));
    for (int i = 0; i < getters.length; i++) {
      Preconditions.check(
          getters[i]
              .getAnnotatedReturnType()
              .getType()
              .equals(setters[i].getAnnotatedParameterTypes()[0].getType()),
          String.format(
              "Parameter of %s does not match return type of %s", setters[i], getters[i]));
    }

    // TODO: Ideally, we would have the mutator framework pass in a Lookup for the fuzz test class.
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    AnnotatedType[] instantiatorParameterTypes =
        stream(setters)
            .map(Method::getAnnotatedParameterTypes)
            .flatMap(Arrays::stream)
            .toArray(AnnotatedType[]::new);
    return createChecked(
            factory,
            initialType,
            makeInstantiator(
                unreflectNewInstance(lookup, newInstance), unreflectMethods(lookup, setters)),
            instantiatorParameterTypes,
            newInstance.getDeclaringClass(),
            /* isImmutable= */ false,
            unreflectMethods(lookup, getters))
        .map(m -> m);
  }

  @SuppressWarnings("Immutable")
  private static <R> Optional<SerializingMutator<R>> createChecked(
      ExtendedMutatorFactory factory,
      AnnotatedType initialType,
      Function<Object[], R> instantiator,
      AnnotatedType[] instantiatorParameterTypes,
      Class<?> instantiatedClass,
      boolean isImmutable,
      MethodHandle... getters) {
    Supplier<SerializingMutator<Object[]>> mutator =
        () ->
            toArrayOrEmpty(
                    stream(instantiatorParameterTypes)
                        .map(type -> propagatePropertyConstraints(initialType, type))
                        .map(factory::tryCreate),
                    SerializingMutator<?>[]::new)
                .map(MutatorCombinators::mutateProduct)
                .orElseThrow(FailedToConstructChildMutatorException::new);
    Function<Object[], R> map =
        components -> {
          try {
            return (R) instantiator.apply(components);
          } catch (Throwable e) {
            throw new RuntimeException(e);
          }
        };
    Function<R, Object[]> inverse =
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
        };
    BiFunction<SerializingMutator<Object[]>, Predicate<Debuggable>, String> debug =
        (productMutator, inCycle) ->
            productMutator.toDebugString(inCycle) + " -> " + instantiatedClass.getSimpleName();
    try {
      if (isImmutable) {
        return Optional.of(
            mutateThenMapToImmutable(mutator, map, inverse, debug, factory::internMutator));
      } else {
        return Optional.of(mutateThenMap(mutator, map, inverse, debug, factory::internMutator));
      }
    } catch (FailedToConstructChildMutatorException e) {
      return Optional.empty();
    }
  }

  private static <R> Function<Object[], R> makeInstantiator(
      MethodHandle newInstance, MethodHandle... setters) {
    boolean settersAreChainable =
        stream(setters)
            .map(MethodHandle::type)
            .map(MethodType::returnType)
            .allMatch(returnType -> returnType.equals(newInstance.type().returnType()));
    // If all setters are chainable, it's possible that the object is actually immutable and the
    // setters return a new instance. In that case, we need to chain the setters in the instantiator
    // or we will always return the default instance.
    if (settersAreChainable) {
      return objects -> {
        try {
          R instance = (R) newInstance.invoke();
          for (int i = 0; i < setters.length; i++) {
            instance = (R) setters[i].invoke(instance, objects[i]);
          }
          return instance;
        } catch (Throwable e) {
          throw new RuntimeException(e);
        }
      };
    } else {
      return objects -> {
        try {
          R instance = (R) newInstance.invoke();
          for (int i = 0; i < setters.length; i++) {
            setters[i].invoke(instance, objects[i]);
          }
          return instance;
        } catch (Throwable e) {
          throw new RuntimeException(e);
        }
      };
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
