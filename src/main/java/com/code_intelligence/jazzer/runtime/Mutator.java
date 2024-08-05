/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

import com.github.fmeum.rules_jni.RulesJni;

public final class Mutator {
  // Disable native mutations via environment variable in mutator unit tests,
  // or via class name check in selffuzz integration tests.
  @SuppressWarnings("ConstantValue")
  public static final boolean SHOULD_MOCK =
      Boolean.parseBoolean(System.getenv("JAZZER_MOCK_LIBFUZZER_MUTATOR"))
          || Mutator.class.getName().startsWith("com.code_intelligence.selffuzz.");

  static {
    if (!SHOULD_MOCK) {
      RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
    }
  }

  public static native int defaultMutateNative(byte[] buffer, int size);

  private Mutator() {}
}
