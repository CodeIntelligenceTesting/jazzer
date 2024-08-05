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
import com.github.fmeum.rules_jni.RulesJni;

public class ExampleFuzzerWithNative {
  static {
    String native_lib = System.getenv("EXAMPLE_NATIVE_LIB");
    RulesJni.loadLibrary(native_lib, ExampleFuzzerWithNative.class);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    int val = data.consumeInt();
    String stringData = data.consumeRemainingAsString();
    if (val == 17759716 && stringData.length() > 10 && stringData.contains("jazzer")) {
      // call native function which contains a crash
      new ExampleFuzzerWithNative().parse(stringData);
    }
  }

  private native boolean parse(String bytes);
}
