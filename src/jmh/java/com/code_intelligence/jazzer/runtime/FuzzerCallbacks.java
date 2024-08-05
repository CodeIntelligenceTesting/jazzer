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

public final class FuzzerCallbacks {
  static {
    RulesJni.loadLibrary("fuzzer_callbacks", FuzzerCallbacks.class);
  }

  static native void traceCmpInt(int arg1, int arg2, int pc);

  static native void traceSwitch(long val, long[] cases, int pc);

  static native void traceMemcmp(byte[] b1, byte[] b2, int result, int pc);

  static native void traceStrstr(String s1, String s2, int pc);
}
