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
import java.util.function.Predicate;
import java.util.stream.Stream;

class BeanSupport {

  static Optional<Class<?>> optionalClassForName(String targetClassName) {
    try {
      return Optional.of(Class.forName(targetClassName));
    } catch (ClassNotFoundException ignored) {
      return Optional.empty();
    }
  }

  static boolean isConcreteClass(Class<?> clazz) {
    return !Modifier.isAbstract(clazz.getModifiers());
  }

  // Sort constructors by parameter count descending, then type names.
  private static final Comparator<Constructor<?>> byDescParameterCountAndTypes =
      comparingInt((Constructor<?> c) -> c.getParameterCount())
          .reversed()
          .thenComparing(c -> Arrays.toString(c.getParameterTypes()));

  static Stream<Constructor<?>> findConstructorsByParameterCount(Class<?> clazz) {
    return stream(clazz.getDeclaredConstructors())
        .filter(constructor -> !Modifier.isPrivate(constructor.getModifiers()))
        // If multiple constructors are defined, prefer the one with the most parameters.
        .sorted(byDescParameterCountAndTypes);
  }

  static Optional<Constructor<?>> findDefaultConstructor(Class<?> clazz) {
    try {
      // Find constructors with default visibility by not using getConstructors().
      Constructor<?> constructor = clazz.getDeclaredConstructor();
      if (Modifier.isPrivate(constructor.getModifiers())) {
        return Optional.empty();
      }
      return Optional.of(constructor);
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }

  static Optional<Method[]> findGettersByPropertyNames(
      Class<?> clazz, Stream<String> propertyNames) {
    Map<String, Method> gettersByPropertyName =
        findMethods(clazz, BeanSupport::isGetter)
            .collect(toMap(BeanSupport::toPropertyName, method -> method, (a, b) -> a));
    return toArrayOrEmpty(
        propertyNames.map(gettersByPropertyName::get).map(Optional::ofNullable), Method[]::new);
  }

  static Optional<Method[]> findGettersByPropertyTypes(Class<?> clazz, Stream<Class<?>> types) {
    Map<Class<?>, List<Method>> gettersByType =
        findMethods(clazz, BeanSupport::isGetter).collect(groupingBy(Method::getReturnType));
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

  static Stream<Method> allMethods(Class<?> clazz) {
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

  static Stream<Method> findMethods(Class<?> clazz, Predicate<Method> check) {
    return allMethods(clazz).filter(check).sorted(comparing(Method::getName));
  }

  static boolean isGetter(Method method) {
    return method.getParameterCount() == 0
        && !method.getReturnType().equals(void.class)
        && !Modifier.isPrivate(method.getModifiers())
        && !method.getName().equals("getClass")
        && (method.getName().startsWith("get")
            || (method.getName().startsWith("is")
                && (method.getReturnType().equals(boolean.class)
                    || method.getReturnType().equals(Boolean.class))));
  }

  static boolean isSetter(Method method) {
    return method.getParameterCount() == 1
        && !Modifier.isPrivate(method.getModifiers())
        // Allow chainable setters. The "withX" setters are commonly used on immutable
        // types and return a new instance, so for those we need to assert that the
        // return type is the same as the class.
        && (method.getReturnType().equals(void.class)
            || method.getReturnType().isAssignableFrom(method.getDeclaringClass()))
        && (method.getName().startsWith("set") || (method.getName().startsWith("with")));
  }

  private BeanSupport() {}
}
