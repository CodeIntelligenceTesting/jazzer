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

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

/**
 * Hooks for the Jazzer API that add call-site specific identifiers to methods that don't require an
 * explicit id parameter.
 */
@SuppressWarnings("unused")
public final class JazzerApiHooks {
  /**
   * Replaces calls to {@link Jazzer#exploreState(byte)} with calls to {@link
   * Jazzer#exploreState(byte, int)} using the hook id as the id parameter.
   *
   * <p>This allows each call site to be tracked separately without requiring the user to manually
   * provide a unique id.
   */
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.api.Jazzer",
      targetMethod = "exploreState",
      targetMethodDescriptor = "(B)V")
  public static void exploreStateWithId(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Jazzer.exploreState((byte) arguments[0], hookId);
  }

  /**
   * Replaces calls to {@link Jazzer#maximize(long, long, long)} with calls to {@link
   * Jazzer#maximize(long, long, long, int, int)} using {@link Jazzer#DEFAULT_NUM_COUNTERS} and the
   * hook id.
   */
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.api.Jazzer",
      targetMethod = "maximize",
      targetMethodDescriptor = "(JJJ)V")
  public static void maximizeWithDefaultCountersAndId(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Jazzer.maximize(
        (long) arguments[0],
        (long) arguments[1],
        (long) arguments[2],
        Jazzer.DEFAULT_NUM_COUNTERS,
        hookId);
  }

  /**
   * Replaces calls to {@link Jazzer#maximize(long, long, long, int)} with calls to {@link
   * Jazzer#maximize(long, long, long, int, int)} using the hook id.
   */
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.api.Jazzer",
      targetMethod = "maximize",
      targetMethodDescriptor = "(JJJI)V")
  public static void maximizeWithCustomCountersAndId(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Jazzer.maximize(
        (long) arguments[0], (long) arguments[1], (long) arguments[2], (int) arguments[3], hookId);
  }

  /**
   * Replaces calls to {@link Jazzer#minimize(long, long, long)} with calls to {@link
   * Jazzer#minimize(long, long, long, int, int)} using {@link Jazzer#DEFAULT_NUM_COUNTERS} and the
   * hook id.
   */
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.api.Jazzer",
      targetMethod = "minimize",
      targetMethodDescriptor = "(JJJ)V")
  public static void minimizeWithDefaultCountersAndId(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Jazzer.minimize(
        (long) arguments[0],
        (long) arguments[1],
        (long) arguments[2],
        Jazzer.DEFAULT_NUM_COUNTERS,
        hookId);
  }

  /**
   * Replaces calls to {@link Jazzer#minimize(long, long, long, int)} with calls to {@link
   * Jazzer#minimize(long, long, long, int, int)} using the hook id.
   */
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "com.code_intelligence.jazzer.api.Jazzer",
      targetMethod = "minimize",
      targetMethodDescriptor = "(JJJI)V")
  public static void minimizeWithCustomCountersAndId(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Jazzer.minimize(
        (long) arguments[0], (long) arguments[1], (long) arguments[2], (int) arguments[3], hookId);
  }
}
