package com.code_intelligence.jazzer.sanitizers.utils;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class ReflectionUtils {

  public static final class ReflectionError extends Error {
    public ReflectionError(Throwable cause) {
      super(cause);
    }
  }

  public static Class<?> clazz(String className) {
    try {
      return Class.forName(className);
    } catch (ClassNotFoundException e) {
      throw new ReflectionError(e);
    }
  }

  public static Class<?> nestedClass(Class<?> parentClass, String nestedClassName) {
    return clazz(parentClass.getName() + "$" + nestedClassName);
  }

  public static Constructor<?> constructor(Class<?> clazz, Class<?>... parameterTypes) {
    try {
      Constructor<?> constructor = clazz.getDeclaredConstructor(parameterTypes);
      constructor.setAccessible(true);
      return constructor;
    } catch (NoSuchMethodException e) {
      throw new ReflectionError(e);
    }
  }

  public static Object newInstance(Constructor<?> constructor, Object... initargs) {
    try {
      return constructor.newInstance(initargs);
    } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
      throw new ReflectionError(e);
    }
  }

  public static Method method(Class<?> clazz, String methodName, Class<?>... parameterTypes) {
    try {
      Method method = clazz.getDeclaredMethod(methodName, parameterTypes);
      method.setAccessible(true);
      return method;
    } catch (NoSuchMethodException e) {
      throw new ReflectionError(e);
    }
  }

  public static Field field(Class<?> clazz, String fieldName) {
    try {
      Field field = clazz.getDeclaredField(fieldName);
      field.setAccessible(true);
      return field;
    } catch (NoSuchFieldException e) {
      throw new ReflectionError(e);
    }
  }

  public static Field fieldOrNull(Class<?> clazz, String fieldName) {
    try {
      return field(clazz, fieldName);
    } catch (ReflectionError e) {
      return null;
    }
  }

  public static Object fieldGet(Field field, Object obj) {
    try {
      return field.get(obj);
    } catch (IllegalAccessException e) {
      throw new ReflectionError(e);
    }
  }

  public static void fieldSet(Field field, Object obj, Object value) {
    try {
      field.set(obj, value);
    } catch (IllegalAccessException e) {
      throw new ReflectionError(e);
    }
  }

  public static int intFieldGet(Field field, Object obj) {
    try {
      return field.getInt(obj);
    } catch (IllegalAccessException e) {
      throw new ReflectionError(e);
    }
  }
}
