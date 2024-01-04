/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.StreamSupport.getOrEmpty;
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
import java.util.stream.Stream;

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
                      // Allow chainable setters. The "withX" setters are commonly used on immutable
                      // types and return a new instance, so for those we need to assert that the
                      // return type is the same as the class.
                      .filter(
                          method ->
                              method.getReturnType().equals(void.class)
                                  || method.getReturnType().equals(clazz))
                      .filter(
                          method ->
                              method.getName().startsWith("set")
                                  || (method.getName().startsWith("with")
                                      && method.getReturnType().equals(clazz)))
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
    return Stream.of("get", "set", "is", "with")
        .flatMap(prefix -> getOrEmpty(trimPrefix(method.getName(), prefix)))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Unexpected method name: " + method.getName()));
  }

  private static Optional<String> trimPrefix(String name, String prefix) {
    if (name.startsWith(prefix)) {
      return Optional.of(name.substring(prefix.length()));
    } else {
      return Optional.empty();
    }
  }
}
