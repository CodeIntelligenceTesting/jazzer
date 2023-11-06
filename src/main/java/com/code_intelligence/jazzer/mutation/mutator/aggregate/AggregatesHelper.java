/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.fixedValue;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.util.Arrays.stream;
import static java.util.Collections.unmodifiableList;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory.FailedToConstructChildMutatorException;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import com.google.errorprone.annotations.ImmutableTypeParameter;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class AggregatesHelper {

  // Aggregate types can be recursive, so we have to reuse the mutator we are about to construct
  // when constructing child mutators.
  private final Map<List<Executable>, Optional<SerializingMutator<?>>> internedMutators =
      new HashMap<>();

  @SuppressWarnings("Immutable")
  public Optional<SerializingMutator<?>> ofImmutable(
      ExtendedMutatorFactory factory, Executable instantiator, Method... getters) {
    Preconditions.check(
        instantiator instanceof Constructor || Modifier.isStatic(instantiator.getModifiers()),
        String.format("Instantiator %s must be a static method or a constructor", instantiator));
    Preconditions.check(
        instantiator.getAnnotatedReturnType().getType() != Void.class,
        String.format("Return type of %s must not be void", instantiator));
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

    Optional<SerializingMutator<?>> mutator =
        internedMutators.get(getCacheKey(instantiator, getters));
    if (mutator == null) {
      mutator =
          ofImmutableChecked(factory, instantiator, getters).map(m -> (SerializingMutator<?>) m);
    } else {
      // A mutator for this aggregate type has already been created, which is the case in particular
      // if it is recursive, i.e., transitively has a field of the same type. We inform the parent
      // mutator to prevent this structure from blowing up, e.g., due to the mutator for nullable
      // types being biased to initialize to a non-null value.
      // TODO: This results in false positives if e.g. a record A has two fields of type record B.
      //  Instead of in a static field, we should intern mutators in a stack maintained by the
      //  ChainedMutatorFactory, with push and pop operations matching the tryCreate calls.
      mutator = mutator.map(MutatorCombinators::markAsRequiringRecursionBreaking);
    }
    return mutator;
  }

  private <@ImmutableTypeParameter T> Optional<SerializingMutator<T>> ofImmutableChecked(
      ExtendedMutatorFactory factory, Executable instantiator, Method... getters) {
    // TODO: Ideally, we would have the mutator framework pass in a Lookup for the fuzz test class.
    instantiator.setAccessible(true);
    for (Method getter : getters) {
      getter.setAccessible(true);
    }
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    MethodHandle instantiatorHandle;
    try {
      if (instantiator instanceof Method) {
        instantiatorHandle = lookup.unreflect((Method) instantiator);
      } else {
        instantiatorHandle = lookup.unreflectConstructor((Constructor<?>) instantiator);
      }
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
    MethodHandle[] getterHandles =
        stream(getters)
            .map(
                getter -> {
                  try {
                    return lookup.unreflect(getter);
                  } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                  }
                })
            .toArray(MethodHandle[]::new);

    if (getters.length == 0) {
      try {
        return Optional.of(fixedValue((T) instantiatorHandle.invoke()));
      } catch (Throwable e) {
        throw new RuntimeException(e);
      }
    }

    try {
      return Optional.of(
          mutateThenMapToImmutable(
              () ->
                  ((Optional<SerializingMutator<?>[]>)
                          toArrayOrEmpty(
                              stream(instantiator.getAnnotatedParameterTypes())
                                  .map(factory::tryCreate),
                              SerializingMutator[]::new))
                      .map(MutatorCombinators::mutateProduct)
                      .orElseThrow(FailedToConstructChildMutatorException::new),
              components -> {
                try {
                  return (T) instantiatorHandle.invokeWithArguments(components);
                } catch (Throwable e) {
                  throw new RuntimeException(e);
                }
              },
              object -> {
                Object[] objects = new Object[getterHandles.length];
                for (int i = 0; i < getterHandles.length; i++) {
                  try {
                    objects[i] = getterHandles[i].invoke(object);
                  } catch (Throwable e) {
                    throw new RuntimeException(e);
                  }
                }
                return objects;
              },
              (productMutator, inCycle) ->
                  productMutator.toDebugString(inCycle)
                      + " -> "
                      + instantiator.getDeclaringClass().getSimpleName(),
              mutator ->
                  internedMutators.put(getCacheKey(instantiator, getters), Optional.of(mutator))));
    } catch (FailedToConstructChildMutatorException e) {
      internedMutators.put(getCacheKey(instantiator, getters), Optional.empty());
      return Optional.empty();
    }
  }

  private static List<Executable> getCacheKey(Executable instantiator, Method... getters) {
    List<Executable> key = new ArrayList<>();
    key.add(instantiator);
    key.addAll(Arrays.asList(getters));
    return unmodifiableList(key);
  }
}
