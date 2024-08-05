/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.driver;

import com.github.fmeum.rules_jni.RulesJni;
import sun.misc.Signal;

public final class SignalHandler {
  static {
    RulesJni.loadLibrary("jazzer_signal_handler", SignalHandler.class);
    Signal.handle(new Signal("INT"), sig -> handleInterrupt());
  }

  public static void initialize() {
    // Implicitly runs the static initializer.
  }

  private static native void handleInterrupt();
}
