/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Executable;

@SuppressWarnings("unused")
public final class TraceIndirHooks {
  // The reflection hook is of type AFTER as it should only report calls that did not fail because
  // of incorrect arguments passed.
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.reflect.Method",
      targetMethod = "invoke")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.reflect.Constructor",
      targetMethod = "newInstance")
  public static void methodInvoke(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object returnValue) {
    TraceDataFlowNativeCallbacks.traceReflectiveCall((Executable) thisObject, hookId);
  }
}
