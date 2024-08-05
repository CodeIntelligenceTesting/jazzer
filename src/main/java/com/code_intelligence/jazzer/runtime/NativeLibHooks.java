/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 *
 * This file also contains code licensed under Apache2 license.
 */

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

@SuppressWarnings("unused")
public final class NativeLibHooks {
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Runtime",
      targetMethod = "loadLibrary",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.System",
      targetMethod = "loadLibrary",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Runtime",
      targetMethod = "load",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.System",
      targetMethod = "load",
      targetMethodDescriptor = "(Ljava/lang/String;)V")
  public static void loadLibraryHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    if (Constants.IS_ANDROID) {
      return;
    }

    TraceDataFlowNativeCallbacks.handleLibraryLoad();
  }
}
