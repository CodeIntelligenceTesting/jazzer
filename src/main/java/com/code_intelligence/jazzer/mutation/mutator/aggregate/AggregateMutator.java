package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.fixedValue;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
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
import java.util.Optional;
import java.util.function.Predicate;

final class AggregateMutator {

  public static <@ImmutableTypeParameter T> Optional<SerializingMutator<T>> ofImmutable(
      MutatorFactory factory, Executable instantiator, Method... getters) {
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

    MethodHandles.Lookup lookup = MethodHandles.lookup().in(instantiator.getDeclaringClass());
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

    String debugStringSuffix = " -> " + instantiator.getDeclaringClass().getSimpleName();
    return ((Optional<SerializingMutator<?>[]>)
            toArrayOrEmpty(
                stream(instantiator.getAnnotatedParameterTypes()).map(factory::tryCreate),
                SerializingMutator[]::new))
        .map(MutatorCombinators::mutateProduct)
        .map(
            productMutator ->
                mutateThenMapToImmutable(
                    productMutator,
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
                    (Predicate<Debuggable> inCycle) ->
                        productMutator.toDebugString(inCycle) + debugStringSuffix));
  }

  private AggregateMutator() {}
}
