/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.sanitizers.utils;

import java.lang.reflect.Field;
import sun.misc.Unsafe;

public final class ReflectionUtils {
  public static final long INVALID_OFFSET = Long.MIN_VALUE;

  private static final boolean JAZZER_REFLECTION_DEBUG =
      "1".equals(System.getenv("JAZZER_REFLECTION_DEBUG"));

  public static Class<?> clazz(String className) {
    try {
      return Class.forName(className);
    } catch (ClassNotFoundException e) {
      if (JAZZER_REFLECTION_DEBUG) e.printStackTrace();
      return null;
    }
  }

  public static Class<?> nestedClass(Class<?> parentClass, String nestedClassName) {
    return clazz(parentClass.getName() + "$" + nestedClassName);
  }

  public static Field field(Class<?> clazz, String name, Class<?> type) {
    if (clazz == null) return null;
    try {
      Field field = clazz.getDeclaredField(name);
      if (!field.getType().equals(type)) {
        throw new NoSuchFieldException(
            "Expected " + name + " to be of type " + type + " (is: " + field.getType() + ")");
      }
      return field;
    } catch (NoSuchFieldException e) {
      if (JAZZER_REFLECTION_DEBUG) e.printStackTrace();
      return null;
    }
  }

  public static long offset(Unsafe unsafe, Field field) {
    if (unsafe == null || field == null) return INVALID_OFFSET;
    return unsafe.objectFieldOffset(field);
  }
}
