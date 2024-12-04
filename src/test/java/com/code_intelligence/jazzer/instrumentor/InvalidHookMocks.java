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
