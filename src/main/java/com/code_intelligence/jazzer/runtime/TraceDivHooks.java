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
