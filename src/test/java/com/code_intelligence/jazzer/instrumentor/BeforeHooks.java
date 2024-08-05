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

public class BeforeHooks {
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.BeforeHooksTarget",
      targetMethod = "hasFunc1BeenCalled",
      targetMethodDescriptor = "()Z")
  public static void patchHasFunc1BeenCalled(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    ((BeforeHooksTargetContract) thisObject).func1();
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.BeforeHooksTarget",
      targetMethod = "getTimesCalled",
      targetMethodDescriptor = "()Ljava/lang/Integer;")
  public static void patchHasBeenCalled(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
    // Invoke static method getTimesCalled() again to pass the test.
    method.invoke();
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "com.code_intelligence.jazzer.instrumentor.BeforeHooksTarget",
      targetMethod = "hasFuncWithArgsBeenCalled")
  public static void patchHasFuncWithArgsBeenCalled(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (arguments.length == 2
        && arguments[0] instanceof Boolean
        && arguments[1] instanceof String) {
      // only if the arguments passed to the hook match the expected argument types and count invoke
      // the method to pass the test
      ((BeforeHooksTargetContract) thisObject).setFuncWithArgsCalled((Boolean) arguments[0]);
    }
  }
}
