/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

@SuppressWarnings({"unused", "RedundantThrows"})
class InvalidHookMocks {
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.String", targetMethod = "equals")
  public static void incorrectHookIdType(
      MethodHandle method, String thisObject, Object[] arguments, long hookId) {}

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "equals")
  private static void invalidAfterHook(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      Boolean returnValue) {}

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "equals")
  public void invalidAfterHook2(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      boolean returnValue) {}

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.String",
      targetMethod = "equals",
      targetMethodDescriptor = "(Ljava/lang/Object;)Z")
  public static String incorrectReturnType(
      MethodHandle method, String thisObject, Object[] arguments, int hookId) {
    return "foo";
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.String",
      targetMethod = "equals")
  public static boolean invalidReplaceHook2(
      MethodHandle method, Integer thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.System",
      targetMethod = "gc",
      targetMethodDescriptor = "()V")
  public static Object invalidReplaceVoidMethod(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return null;
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.StringBuilder",
      targetMethod = "<init>",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  public static Object invalidReturnType(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
    return null;
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "startsWith",
      targetMethodDescriptor = "(Ljava/lang/String;)Z")
  public static void primitiveReturnValueMustBeWrapped(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      boolean returnValue) {}

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.StringBuilder",
      targetMethod = "<init>",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  public static void replaceOnInitWithoutReturnType(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {}

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.StringBuilder",
      targetMethod = "<init>",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  public static Object replaceOnInitWithIncompatibleType(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
    return new Object();
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "equals")
  public static void primitiveReturnType(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      boolean returnValue) {}
}
