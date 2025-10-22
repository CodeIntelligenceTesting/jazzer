/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

/**
 * Guides inputs passed to {@link java.math.BigDecimal} constructors towards forms with huge
 * exponents (e.g., 1e1000000) to trigger performance issues like timeouts or OOMs.
 */
public final class BigDecimal {

  private static final String HUGE_EXPONENT = "1e1000000";

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.math.BigDecimal",
      targetMethod = "<init>")
  public static void bigDecimalConstructorHook(
      MethodHandle method, Object thisObject, Object[] args, int hookId) {
    if (args.length == 0 || args[0] == null) {
      return;
    }

    String s = null;
    Object first = args[0];
    if (first instanceof String) {
      s = (String) first;
    } else if (first instanceof char[]) {
      s = new String((char[]) first);
    }

    if (s == null || s.isEmpty()) {
      return;
    }

    // Nudge the fuzzer towards a BigDecimal string with a huge exponent.
    Jazzer.guideTowardsEquality(s, HUGE_EXPONENT, hookId);
  }
}
