/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.github.fmeum.rules_jni.RulesJni;

public class NativeValueProfileFuzzer {
  public static void fuzzerInitialize() {
    RulesJni.loadLibrary("native_value_profile_fuzzer", NativeValueProfileFuzzer.class);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    long[] blocks = data.consumeLongs(2);
    if (blocks.length != 2) return;
    if (checkAccess(blocks[0], blocks[1])) {
      throw new FuzzerSecurityIssueLow("Security breached");
    }
  }

  private static native boolean checkAccess(long block1, long block2);
}
