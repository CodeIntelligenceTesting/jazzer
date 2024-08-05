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
import java.io.UnsupportedEncodingException;

/**
 * Optimized implementations of the libFuzzer callbacks that do not rely on the deprecated
 * CriticalJNINatives feature. Methods with `Java` in their name implement some parts in Java.
 */
public final class FuzzerCallbacksOptimizedNonCritical {
  static {
    RulesJni.loadLibrary("fuzzer_callbacks", FuzzerCallbacksOptimizedNonCritical.class);
  }

  static native void traceSwitch(long val, long[] cases, int pc);

  static native void traceMemcmp(byte[] b1, byte[] b2, int result, int pc);

  static native void traceStrstr(String s1, String s2, int pc);

  static void traceStrstrJava(String haystack, String needle, int pc)
      throws UnsupportedEncodingException {
    // Note that we are not encoding as modified UTF-8 here: The FuzzedDataProvider transparently
    // converts CESU8 into modified UTF-8 by coding null bytes on two bytes. Since the fuzzer is
    // more likely to insert literal null bytes, having both the fuzzer input and the reported
    // string comparisons be CESU8 should perform even better than the current implementation using
    // modified UTF-8.
    traceStrstrInternal(needle.substring(0, Math.min(needle.length(), 64)).getBytes("CESU8"), pc);
  }

  private static native void traceStrstrInternal(byte[] needle, int pc);
}
