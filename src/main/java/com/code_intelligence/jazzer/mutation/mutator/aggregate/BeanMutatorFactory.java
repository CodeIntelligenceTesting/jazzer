/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.StreamSupport.toArrayOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.util.Arrays.stream;
import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toMap;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Map;
import java.util.Optional;

final class BeanMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {

    return asSubclassOrEmpty(type, Object.class)
        .flatMap(
            clazz -> {
              if (Modifier.isAbstract(clazz.getModifiers())) {
                return Optional.empty();
              }
              Constructor<?> constructor;
              try {
                // Also find constructors with default visibility by not using getConstructors().
                constructor = clazz.getDeclaredConstructor();
                if (Modifier.isPrivate(constructor.getModifiers())) {
                  return Optional.empty();
                }
              } catch (NoSuchMethodException e) {
                return Optional.empty();
              }

              Method[] setters =
                  stream(clazz.getMethods())
                      .filter(method -> method.getParameterCount() == 1)
                      // Allow chainable setters.
                      .filter(
                          method ->
                              method.getReturnType().equals(void.class)
                                  || method.getReturnType().equals(clazz))
                      .filter(method -> method.getName().startsWith("set"))
                      // Sort for deterministic ordering.
                      .sorted(comparing(Method::getName))
                      .toArray(Method[]::new);

              Map<String, Method> gettersByPropertyName =
                  stream(clazz.getMethods())
                      .filter(method -> method.getParameterCount() == 0)
                      .filter(method -> !method.getReturnType().equals(void.class))
                      .filter(method -> !method.getName().equals("getClass"))
                      .filter(
                          method ->
                              method.getName().startsWith("get")
                                  || (method.getName().startsWith("is")
                                      && (method.getReturnType().equals(boolean.class)
                                          || method.getReturnType().equals(Boolean.class))))
                      // If there are both a getX and an isX method, sorting is required for the
                      // getX method to be picked deterministically in the following collection.
                      .sorted(comparing(Method::getName))
                      .collect(
                          toMap(
                              BeanMutatorFactory::getPropertyName, method -> method, (a, b) -> a));

              // A Java bean can have additional getters corresponding to computed properties, but
              // we require that all setters have a corresponding getter.
              // TODO: Should we also allow setters without a corresponding getter, as common on
              //  builders? The getters could be replaced with a WeakIdentityHashMap storing the
              //  values passed into the instantiator.
              Optional<Method[]> maybeGetters =
                  toArrayOrEmpty(
                      stream(setters)
                          .map(BeanMutatorFactory::getPropertyName)
                          .map(gettersByPropertyName::get)
                          .map(Optional::ofNullable),
                      Method[]::new);
              if (!maybeGetters.isPresent()) {
                return Optional.empty();
              }
              Method[] getters = maybeGetters.get();

              for (int i = 0; i < getters.length; i++) {
                if (!getters[i]
                    .getAnnotatedReturnType()
                    .getType()
                    .equals(setters[i].getAnnotatedParameterTypes()[0].getType())) {
                  // The getter and setter don't have matching types.
                  // TODO: Support Optional<T> getters, which often have a corresponding T setter.
                  return Optional.empty();
                }
              }

              return AggregatesHelper.ofMutable(factory, constructor, getters, setters);
            });
  }

  private static String getPropertyName(Method method) {
    String name = method.getName();
    if (name.startsWith("get")) {
      return name.substring("get".length());
    } else if (name.startsWith("set")) {
      return name.substring("set".length());
    } else if (name.startsWith("is")) {
      return name.substring("is".length());
    } else {
      throw new AssertionError("Unexpected method name: " + name);
    }
  }
}
