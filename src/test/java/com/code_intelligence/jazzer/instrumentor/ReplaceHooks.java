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

@SuppressWarnings("unused")
public class ReplaceHooks {
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnTrue1")
  public static boolean patchShouldReturnTrue1(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnTrue2")
  public static Boolean patchShouldReturnTrue2(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnTrue3")
  public static Object patchShouldReturnTrue3(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnFalse1")
  public static Boolean patchShouldReturnFalse1(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return false;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnFalse2")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnFalse3")
  public static Object patchShouldReturnFalse2(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return false;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldReturnReversed",
      targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/String;")
  public static String patchShouldReturnReversed(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return new StringBuilder((String) arguments[0]).reverse().toString();
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldIncrement")
  public static int patchShouldIncrement(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return ((int) arguments[0]) + 1;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "shouldCallPass")
  public static void patchShouldCallPass(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    ((ReplaceHooksTargetContract) thisObject).pass("shouldCallPass");
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksTarget",
      targetMethod = "idempotent",
      targetMethodDescriptor = "(I)I")
  public static int patchIdempotent(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
    // Iterate the function twice to pass the test.
    int input = (int) arguments[0];
    int temp = (int) method.invokeWithArguments(thisObject, input);
    return (int) method.invokeWithArguments(thisObject, temp);
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.util.AbstractList",
      targetMethod = "get",
      targetMethodDescriptor = "(I)Ljava/lang/Object;")
  public static Object patchAbstractListGet(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.util.Set",
      targetMethod = "contains",
      targetMethodDescriptor = "(Ljava/lang/Object;)Z")
  public static boolean patchSetGet(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return true;
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksInit",
      targetMethod = "<init>",
      targetMethodDescriptor = "()V")
  public static ReplaceHooksInit patchInit(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    // Test with subclass
    return new ReplaceHooksInit() {
      {
        initialized = true;
      }
    };
  }

  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.ReplaceHooksInit",
      targetMethod = "<init>",
      targetMethodDescriptor = "(ZLjava/lang/String;)V")
  public static ReplaceHooksInit patchInitWithParams(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    return new ReplaceHooksInit(true, "");
  }
}
