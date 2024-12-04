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

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.ReflectionSupport.unreflectMethod;
import static com.code_intelligence.jazzer.mutation.support.ReflectionSupport.unreflectMethods;
import static com.code_intelligence.jazzer.mutation.support.ReflectionSupport.unreflectNewInstance;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.suppliedOrEmpty;
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
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

final class AggregatesHelper {

  static Optional<SerializingMutator<?>> createMutator(
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
    return createMutator(
            factory,
            instantiator.getDeclaringClass(),
            instantiator.getAnnotatedParameterTypes(),
            asInstantiationFunction(lookup, instantiator),
            makeSingleGetter(unreflectMethods(lookup, getters)),
            initialType,
            isImmutable)
        .map(m -> m);
  }

  static Optional<SerializingMutator<?>> createMutator(
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
    return createMutator(
            factory,
            newInstance.getDeclaringClass(),
            parameterTypes(setters),
            asInstantiationFunction(lookup, newInstance, setters),
            makeSingleGetter(unreflectMethods(lookup, getters)),
            initialType,
            /* isImmutable= */ false)
        .map(m -> m);
  }

  @SuppressWarnings("Immutable")
  static <R> Optional<SerializingMutator<?>> createMutator(
      ExtendedMutatorFactory factory,
      Class<?> instantiatedClass,
      AnnotatedType[] instantiatorParameterTypes,
      Function<Object[], R> map,
      Function<R, Object[]> inverse,
      AnnotatedType initialType,
      boolean isImmutable) {
    Supplier<SerializingMutator<Object[]>> mutator =
        () ->
            toArrayOrEmpty(
                    stream(instantiatorParameterTypes)
                        .map(type -> propagatePropertyConstraints(initialType, type))
                        .map(factory::tryCreate),
                    SerializingMutator<?>[]::new)
                .map(MutatorCombinators::mutateProduct)
                .orElseThrow(FailedToConstructChildMutatorException::new);
    BiFunction<SerializingMutator<Object[]>, Predicate<Debuggable>, String> debug =
        (productMutator, inCycle) ->
            productMutator.toDebugString(inCycle) + " -> " + instantiatedClass.getSimpleName();
    return suppliedOrEmpty(
        () -> {
          if (isImmutable) {
            return mutateThenMapToImmutable(mutator, map, inverse, debug, factory::internMutator);
          } else {
            return mutateThenMap(mutator, map, inverse, debug, factory::internMutator);
          }
        });
  }

  private static <R> Function<R, Object[]> makeSingleGetter(MethodHandle[] getters) {
    return object -> {
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
  }

  static Function<Object[], Object> asInstantiationFunction(
      MethodHandles.Lookup lookup, Executable instantiator) {
    MethodHandle instantiatorHandle = unreflectNewInstance(lookup, instantiator);
    return components -> {
      try {
        return instantiatorHandle.invokeWithArguments(components);
      } catch (Throwable e) {
        throw new RuntimeException(e);
      }
    };
  }

  static Function<Object[], Object> asInstantiationFunction(
      MethodHandles.Lookup lookup, Executable instantiator, Method[] setters) {
    return asInstantiatorFunction(
        unreflectNewInstance(lookup, instantiator), unreflectMethods(lookup, setters));
  }

  static Function<Object[], Object> asInstantiationFunction(
      MethodHandles.Lookup lookup, Method instantiator, Method[] setters) {
    return asInstantiatorFunction(
        unreflectMethod(lookup, instantiator), unreflectMethods(lookup, setters));
  }

  private static <R> Function<Object[], R> asInstantiatorFunction(
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

  static AnnotatedType[] parameterTypes(Method[] methods) {
    return stream(methods)
        .map(Method::getAnnotatedParameterTypes)
        .flatMap(Arrays::stream)
        .toArray(AnnotatedType[]::new);
  }

  private AggregatesHelper() {}
}
