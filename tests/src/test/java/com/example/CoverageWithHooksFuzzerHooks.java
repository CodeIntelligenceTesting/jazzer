/*
 * Copyright 2026 Code Intelligence GmbH
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
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

/**
 * Hook that targets ArrayList.&lt;init&gt; that sets a system property so that we can check in the
 * fuzz test whether the hook is called or not.
 */
public class CoverageWithHooksFuzzerHooks {
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.ArrayList",
      targetMethod = "<init>")
  public static void arrayListInitHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object returnValue) {
    System.setProperty("jazzer.test.hook.called", "true");
  }
}
