/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@SuppressWarnings("InvalidPatternSyntax")
public class DisabledHooksFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    triggerCustomHook();
    triggerBuiltinHook();
  }

  private static void triggerCustomHook() {}

  private static void triggerBuiltinHook() {
    // Trigger the built-in regex injection detector if it is enabled, but catch the exception
    // thrown if it isn't.
    try {
      Pattern.compile("[");
    } catch (PatternSyntaxException ignored) {
    }
  }
}

class DisabledHook {
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "com.example.DisabledHooksFuzzer",
      targetMethod = "triggerCustomHook",
      targetMethodDescriptor = "()V")
  public static void triggerCustomHookHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Jazzer.reportFindingFromHook(
        new IllegalStateException("hook on triggerCustomHook should have been disabled"));
  }
}
