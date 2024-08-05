/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

/** The type of a {@link MethodHook}. */
// Note: The order of entries is important and is used during instrumentation.
public enum HookType {
  BEFORE,
  REPLACE,
  AFTER,
}
