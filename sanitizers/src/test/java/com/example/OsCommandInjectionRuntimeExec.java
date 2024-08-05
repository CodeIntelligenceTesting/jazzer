/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static java.lang.Runtime.getRuntime;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.concurrent.TimeUnit;

public class OsCommandInjectionRuntimeExec {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsAsciiString();
    try {
      Process process = getRuntime().exec(input, new String[] {});
      // This should be way faster, but we have to wait until the call is done
      if (!process.waitFor(10, TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
      }
    } catch (Exception ignored) {
      // Ignore execution and setup exceptions
    }
  }
}
