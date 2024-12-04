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
