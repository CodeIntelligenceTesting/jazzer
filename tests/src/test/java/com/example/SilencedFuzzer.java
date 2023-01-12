/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.io.OutputStream;
import java.io.PrintStream;

public class SilencedFuzzer {
  private static final PrintStream noopStream = new PrintStream(new OutputStream() {
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
