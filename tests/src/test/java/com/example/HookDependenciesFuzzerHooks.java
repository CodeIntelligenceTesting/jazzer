/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
