/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

public class ExampleFuzzerHooks {
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "java.security.SecureRandom",
      targetMethod = "nextLong",
      targetMethodDescriptor = "()J")
  public static long getRandomNumber(
      MethodHandle handle, Object thisObject, Object[] args, int hookId) {
    return 4; // chosen by fair dice roll.
    // guaranteed to be random.
    // https://xkcd.com/221/
  }
}
