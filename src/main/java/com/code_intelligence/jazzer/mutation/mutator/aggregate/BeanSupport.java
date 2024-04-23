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
import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;
import static java.util.Comparator.comparing;
import static java.util.Comparator.comparingInt;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toMap;

import java.beans.Introspector;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class BeanSupport {

  // Sort constructors by parameter count descending, then type names.
  private static final Comparator<Constructor<?>> byDescParameterCountAndTypes =
      comparingInt((Constructor<?> c) -> c.getParameterCount())
          .reversed()
          .thenComparing(c -> Arrays.toString(c.getParameterTypes()));

  static List<Constructor<?>> findConstructorsByParameterCount(Class<?> clazz) {
    return stream(clazz.getDeclaredConstructors())
        .filter(constructor -> !Modifier.isPrivate(constructor.getModifiers()))
        .filter(constructor -> constructor.getParameterCount() > 0)
        // If multiple constructors are defined, prefer the one with the most
        // parameters.
        .sorted(byDescParameterCountAndTypes)
        .collect(Collectors.toList());
  }

  static Optional<Method[]> findGettersByPropertyNames(
      Class<?> clazz, Stream<String> propertyNames) {
    Map<String, Method> gettersByPropertyName =
        getGetters(clazz)
            .collect(toMap(BeanSupport::toPropertyName, method -> method, (a, b) -> a));
    return toArrayOrEmpty(
        propertyNames.map(gettersByPropertyName::get).map(Optional::ofNullable), Method[]::new);
  }

  static Optional<Method[]> findGettersByPropertyTypes(Class<?> clazz, Stream<Class<?>> types) {
    Map<Class<?>, List<Method>> gettersByType =
        getGetters(clazz).collect(groupingBy(Method::getReturnType));
    return toArrayOrEmpty(
        types.map(
            type -> {
              // If none or multiple getters exist for a type, the corresponding getter can not be
              // determined.
              List<Method> getters = gettersByType.getOrDefault(type, emptyList());
              if (getters.size() == 1) {
                return Optional.of(getters.get(0));
              } else {
                return Optional.empty();
              }
            }),
        Method[]::new);
  }

  static Stream<Method> getGetters(Class<?> clazz) {
    return allMethods(clazz)
        .filter(BeanSupport::isGetter)
        // If there are both a getX and an isX method, sorting is required for the
        // getX method to be picked deterministically in the following collection.
        .sorted(comparing(Method::getName));
  }

  private static boolean isGetter(Method method) {
    return method.getParameterCount() == 0
        && !method.getReturnType().equals(void.class)
        && !Modifier.isPrivate(method.getModifiers())
        && !method.getName().equals("getClass")
        && (method.getName().startsWith("get")
            || (method.getName().startsWith("is")
                && (method.getReturnType().equals(boolean.class)
                    || method.getReturnType().equals(Boolean.class))));
  }

  static Stream<Method> getSetters(Class<?> clazz) {
    return allMethods(clazz)
        .filter(BeanSupport::isSetter)
        // Sort for deterministic ordering.
        .sorted(comparing(Method::getName));
  }

  private static boolean isSetter(Method method) {
    return method.getParameterCount() == 1
        && !Modifier.isPrivate(method.getModifiers())
        // Allow chainable setters. The "withX" setters are commonly used on immutable
        // types and return a new instance, so for those we need to assert that the
        // return type is the same as the class.
        && (method.getReturnType().equals(void.class)
            || method.getReturnType().isAssignableFrom(method.getDeclaringClass()))
        && (method.getName().startsWith("set") || (method.getName().startsWith("with")));
  }

  static String toPropertyName(Method method) {
    return Stream.of("get", "set", "is", "with")
        .flatMap(prefix -> getOrEmpty(trimPrefix(method.getName(), prefix)))
        .map(Introspector::decapitalize)
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

  static boolean matchingReturnTypes(Method[] methods, Type[] types) {
    for (int i = 0; i < methods.length; i++) {
      // TODO: Support Optional<T> getters, which often have a corresponding T setter.
      if (!methods[i].getAnnotatedReturnType().getType().equals(types[i])) {
        return false;
      }
    }
    return true;
  }

  private static Stream<Method> allMethods(Class<?> clazz) {
    return allMethods(clazz, new HashMap<>());
  }

  private static Stream<Method> allMethods(Class<?> clazz, Map<String, Method> methods) {
    if (clazz == null) {
      return methods.values().stream();
    }
    for (Method declaredMethod : clazz.getDeclaredMethods()) {
      methods.putIfAbsent(declaredMethod.toString(), declaredMethod);
    }
    return allMethods(clazz.getSuperclass(), methods);
  }

  private BeanSupport() {}
}
