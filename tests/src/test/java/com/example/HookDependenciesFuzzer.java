/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.util.regex.Pattern;

// This fuzzer verifies that:
// 1. a class referenced in a static initializer of a hook is still instrumented with the hook;
// 2. hooks that are not shipped in the Jazzer agent JAR can still instrument Java standard library
//    classes.
public class HookDependenciesFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    try {
      Pattern.matches("foobar", "foobar");
    } catch (Throwable t) {
      if (t instanceof FuzzerSecurityIssueLow) {
        throw t;
      } else {
        // Unexpected exception, exit without producing a finding to let the test fail due to the
        // missing Java reproducer.
        // FIXME(fabian): This is hacky and will result in false positives as soon as we implement
        //  Java reproducers for fuzz target exits. Replace this with a more reliable signal.
        t.printStackTrace();
        System.exit(1);
      }
    }
  }
}
