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
