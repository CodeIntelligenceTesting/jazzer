/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.support;

import static java.util.Arrays.stream;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public final class ReflectionSupport {

  private ReflectionSupport() {}

  public static MethodHandle unreflectNewInstance(
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

  public static MethodHandle[] unreflectMethods(MethodHandles.Lookup lookup, Method... methods) {
    return stream(methods)
        .map(method -> unreflectMethod(lookup, method))
        .toArray(MethodHandle[]::new);
  }

  public static MethodHandle unreflectMethod(MethodHandles.Lookup lookup, Method method) {
    try {
      method.setAccessible(true);
      return lookup.unreflect(method);
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }
}
