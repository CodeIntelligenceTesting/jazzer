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
