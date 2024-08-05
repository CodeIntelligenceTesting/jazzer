/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.driver;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Optional;

class ReflectionUtils {
  static Optional<Method> targetPublicStaticMethod(
      Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      Method method = clazz.getMethod(name, parameterTypes);
      if (!Modifier.isStatic(method.getModifiers()) || !Modifier.isPublic(method.getModifiers())) {
        return Optional.empty();
      }
      return Optional.of(method);
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }
}
