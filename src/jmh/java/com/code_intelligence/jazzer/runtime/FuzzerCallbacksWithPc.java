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

/**
 * Unoptimized implementation of the libFuzzer callbacks that use the trampoline construction to
 * inject fake PCs.
 */
public final class FuzzerCallbacksWithPc {
  static {
    RulesJni.loadLibrary("fuzzer_callbacks", FuzzerCallbacksWithPc.class);
  }

  static native void traceCmpInt(int arg1, int arg2, int pc);

  static native void traceSwitch(long val, long[] cases, int pc);
}
