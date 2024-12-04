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
public final class TraceDivHooks {
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Integer",
      targetMethod = "divideUnsigned",
      targetMethodDescriptor = "(II)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Integer",
      targetMethod = "remainderUnsigned",
      targetMethodDescriptor = "(II)I")
  public static void intUnsignedDivide(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    // Since the arguments are to be treated as unsigned integers we need a long to fit the
    // divisor.
    TraceDataFlowNativeCallbacks.traceDivLong(Integer.toUnsignedLong((int) arguments[1]), hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Long",
      targetMethod = "divideUnsigned",
      targetMethodDescriptor = "(JJ)J")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Long",
      targetMethod = "remainderUnsigned",
      targetMethodDescriptor = "(JJ)J")
  public static void longUnsignedDivide(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    long divisor = (long) arguments[1];
    // Run the callback only if the divisor, which is regarded as an unsigned long, fits in a
    // signed long, i.e., does not have the sign bit set.
    if (divisor > 0) {
      TraceDataFlowNativeCallbacks.traceDivLong(divisor, hookId);
    }
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "divide",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Number;")
  public static void numberUnsignedDivide(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    // Clojure unconditionally casts the argument to Number.
    // https://github.com/clojure/clojure/blob/2a058814e5fa3e8fb630ae507c3fa7dc865138c6/src/jvm/clojure/lang/Numbers.java#L189
    long divisor = ((Number) arguments[1]).longValue();
    // Run the callback only if the divisor, which is regarded as an unsigned long, fits in a
    // signed long, i.e., does not have the sign bit set.
    if (divisor > 0) {
      TraceDataFlowNativeCallbacks.traceDivLong(divisor, hookId);
    }
  }
}
