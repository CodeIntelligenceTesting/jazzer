/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.io.OutputStream;
import java.io.PrintStream;

public class SilencedFuzzer {
  private static final PrintStream noopStream =
      new PrintStream(
          new OutputStream() {
            @Override
            public void write(int b) {}
          });

  public static void fuzzerInitialize() {
    System.setErr(noopStream);
    System.setOut(noopStream);
  }

  public static void fuzzerTestOneInput(byte[] input) {
    // If the FuzzTargetTestWrapper successfully parses the stack trace emitted by this finding, we
    // know that the fuzzer still emitted output despite the fact that System.err and System.out
    // have been redirected above.
    throw new FuzzerSecurityIssueHigh();
  }
}
