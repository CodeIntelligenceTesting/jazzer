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

class ValidHookMocks {
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.String", targetMethod = "equals")
  public static void validBeforeHook(
      MethodHandle method, String thisObject, Object[] arguments, int hookId) {}

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "equals")
  public static void validAfterHook(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      Boolean returnValue) {}

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.String",
      targetMethod = "equals",
      targetMethodDescriptor = "(Ljava/lang/Object;)Z")
  public static Boolean validReplaceHook(
      MethodHandle method, String thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.String",
      targetMethod = "equals")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.lang.String",
      targetMethod = "equalsIgnoreCase")
  public static boolean validReplaceHook2(
      MethodHandle method, String thisObject, Object[] arguments, int hookId) {
    return true;
  }
}
