// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Executable;

@SuppressWarnings("unused")
final public class TraceIndirHooks {
  // The reflection hook is of type AFTER as it should only report calls that did not fail because
  // of incorrect arguments passed.
  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.reflect.Method", targetMethod = "invoke")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.reflect.Constructor",
      targetMethod = "newInstance")
  public static void
  methodInvoke(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object returnValue) {
    TraceDataFlowNativeCallbacks.traceReflectiveCall((Executable) thisObject, hookId);
  }
}
