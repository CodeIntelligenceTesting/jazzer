/*
 * Copyright 2024 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

public final class ForkModeFuzzer {
  public static void fuzzerInitialize() {
    // When running through a Java reproducer, do not check the Java opts.
    if (System.getProperty("jazzer.is_reproducer") != null) return;
    String foo = System.getProperty("foo");
    String bar = System.getProperty("bar");
    String baz = System.getProperty("baz");
    // Only used to verify that arguments are correctly passed down to child processes.
    if (foo == null
        || bar == null
        || baz == null
        || !foo.equals("foo")
        || !(bar.equals("b;ar") || bar.equals("b:ar"))
        || !baz.equals("baz")) {
      // Exit the process with an exit code different from that for a finding.
      System.err.println("ERROR: Did not correctly pass all jvm_args to child process.");
      System.err.printf("foo: %s%nbar: %s%nbaz: %s%n", foo, bar, baz);
      System.exit(3);
    }
    // Only used to verify that Jazzer honors the JAVA_OPTS env var.
    String javaOpts = System.getProperty("java_opts");
    if (javaOpts == null || !javaOpts.equals("1")) {
      // Exit the process with an exit code different from that for a finding.
      System.err.println("ERROR: Did not honor JAVA_OPTS.");
      System.err.printf("java_opts: %s%n", javaOpts);
      System.exit(4);
    }
  }

  public static void fuzzerTestOneInput(byte[] data) {
    throw new FuzzerSecurityIssueLow("Passed fuzzerInitialize");
  }
}
