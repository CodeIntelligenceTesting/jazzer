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

package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.WeakHashMap;

@SuppressWarnings("unused")
public final class ClojureLangHooks {
  /**
   * Used to memoize the all clojure function objects that test for substring. These function
   * objects extend AFunction and do not overwrite equals(), which allows us to use a WeakHashMap.
   */
  static ThreadLocal<Set<Object>> stringContainsFuncs =
      ThreadLocal.withInitial(() -> Collections.newSetFromMap(new WeakHashMap<Object, Boolean>()));

  static final Set<String> stringContainsFuncNames =
      new HashSet<String>(
          Arrays.asList(
              "clojure.string$includes_QMARK_",
              "clojure.string$starts_with_QMARK_",
              "clojure.string$ends_with_QMARK_",
              "clojure.string$index_of_QMARK_",
              "clojure.string$last_index_of_QMARK_"));

  /**
   * This hook checks the type of the returned clojure.lang.IFn objects and puts them into
   * stringContainsFuncs if they match know string-contains functions.
   */
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "clojure.lang.Var",
      targetMethod = "getRawRoot")
  public static void clojureMarkContains(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object result) {
    if (stringContainsFuncNames.contains(result.getClass().getCanonicalName())) {
      stringContainsFuncs.get().add(result);
    }
  }

  /**
   * Actual hook for fuzzer guidance relying on identified objects by the
   * clojure.lang.Var.getRawRoot hook.
   */
  @MethodHook(type = HookType.BEFORE, targetClassName = "clojure.lang.IFn", targetMethod = "invoke")
  public static void clojureMarkedContains(
      MethodHandle method, Object thisObject, Object[] args, int hookId) {
    if (stringContainsFuncs.get().contains(thisObject)) {
      if (args.length >= 2) {
        if (args[0] instanceof String && args[1] instanceof String) {
          Jazzer.guideTowardsContainment((String) args[0], (String) args[1], hookId);
        }
      }
    }
  }
}
