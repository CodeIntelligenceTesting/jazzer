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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Field;
import java.util.regex.Pattern;

public class HookDependenciesFuzzerHooks {
  private static final Field PATTERN_ROOT;

  static {
    Field root;
    try {
      root = Pattern.class.getDeclaredField("root");
    } catch (NoSuchFieldException e) {
      root = null;
    }
    PATTERN_ROOT = root;
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.regex.Matcher",
      targetMethod = "matches",
      targetMethodDescriptor = "()Z",
      additionalClassesToHook = {"java.util.regex.Pattern"})
  public static void matcherMatchesHook(
      MethodHandle method,
      Object alwaysNull,
      Object[] alwaysEmpty,
      int hookId,
      Boolean returnValue) {
    if (PATTERN_ROOT != null) {
      throw new FuzzerSecurityIssueLow("Hook applied even though it depends on the class to hook");
    }
  }
}
