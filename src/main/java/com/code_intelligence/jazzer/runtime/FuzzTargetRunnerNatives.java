/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 *
 * This file also contains code licensed under Apache2 license.
 */

package com.code_intelligence.jazzer.runtime;

import com.github.fmeum.rules_jni.RulesJni;

/**
 * The native functions used by FuzzTargetRunner.
 *
 * <p>This class has to be loaded by the bootstrap class loader since the native library it loads
 * links in libFuzzer and the Java hooks, which have to be on the bootstrap path so that they are
 * seen by Java standard library classes, need to be able to call native libFuzzer callbacks.
 */
public class FuzzTargetRunnerNatives {
  static {
    if (!Constants.IS_ANDROID && FuzzTargetRunnerNatives.class.getClassLoader() != null) {
      throw new IllegalStateException(
          "FuzzTargetRunnerNatives must be loaded in the bootstrap loader");
    }
    RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
  }

  public static native int startLibFuzzer(
      byte[][] args, Class<?> runner, boolean useExperimentalMutator);

  public static native void printAndDumpCrashingInput();

  public static native void temporarilyDisableLibfuzzerExitHook();
}
