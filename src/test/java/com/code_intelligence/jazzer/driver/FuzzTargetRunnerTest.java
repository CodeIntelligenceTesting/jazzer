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

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.agent.AgentInstaller;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.runtime.CoverageMap;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import sun.misc.Unsafe;

public class FuzzTargetRunnerTest {
  private static final Pattern DEDUP_TOKEN_PATTERN =
      Pattern.compile("(?m)^DEDUP_TOKEN: ([0-9a-f]{16})(?:\r\n|\r|\n)");
  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final ByteArrayOutputStream recordedErr = new ByteArrayOutputStream();
  private static final ByteArrayOutputStream recordedOut = new ByteArrayOutputStream();
  private static boolean fuzzerInitializeRan = false;
  private static boolean finishedAllNonCrashingRuns = false;

  public static void fuzzerInitialize() {
    fuzzerInitializeRan = true;
  }

  public static void fuzzerTestOneInput(byte[] data) {
    switch (new String(data, StandardCharsets.UTF_8)) {
      case "no crash":
        CoverageMap.recordCoverage(0);
        return;
      case "first finding":
        CoverageMap.recordCoverage(1);
        throw new IllegalArgumentException("first finding");
      case "second finding":
        CoverageMap.recordCoverage(2);
        Jazzer.reportFindingFromHook(new StackOverflowError("second finding"));
        throw new IllegalArgumentException("not reported");
      case "crash":
        CoverageMap.recordCoverage(3);
        throw new RuntimeException("crash");
    }
  }

  public static void fuzzerTearDown() {
    try {
      String errOutput = new String(recordedErr.toByteArray(), StandardCharsets.UTF_8);
      assert errOutput.contains("== Java Exception: java.lang.RuntimeException: crash");
      String outOutput = new String(recordedOut.toByteArray(), StandardCharsets.UTF_8);
      assert DEDUP_TOKEN_PATTERN.matcher(outOutput).find();

      assert finishedAllNonCrashingRuns : "Did not finish all expected runs before crashing";
      assert CoverageMap.getCoveredIds().equals(Stream.of(0, 1, 2, 3).collect(Collectors.toSet()));
      assert UNSAFE.getByte(CoverageMap.countersAddress) == 2;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 1) == 2;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 2) == 2;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 3) == 1;
    } catch (AssertionError e) {
      e.printStackTrace();
      Runtime.getRuntime().halt(1);
    }
    // FuzzTargetRunner calls _Exit after this function, so the test would fail unless this line is
    // executed. Use halt rather than exit to get around FuzzTargetRunner's shutdown hook calling
    // fuzzerTearDown, which would otherwise result in a shutdown hook loop.
    Runtime.getRuntime().halt(0);
  }

  public static void main(String[] args) {
    PrintStream recordingErr = new TeeOutputStream(new PrintStream(recordedErr, true), System.err);
    System.setErr(recordingErr);
    PrintStream recordingOut = new TeeOutputStream(new PrintStream(recordedOut, true), System.out);
    System.setOut(recordingOut);

    // Do not instrument any classes.
    System.setProperty("jazzer.instrumentation_excludes", "**");
    System.setProperty("jazzer.custom_hook_excludes", "**");
    System.setProperty("jazzer.target_class", FuzzTargetRunnerTest.class.getName());
    // Keep going past all "no crash", "first finding" and "second finding" runs, then crash.
    System.setProperty("jazzer.keep_going", "3");

    AgentInstaller.install(true);
    FuzzTargetHolder.fuzzTarget =
        FuzzTargetFinder.findFuzzTarget(FuzzTargetRunnerTest.class.getName());

    // Use a loop to simulate two findings with the same stack trace and thus verify that keep_going
    // works as advertised.
    for (int i = 1; i < 3; i++) {
      int result = FuzzTargetRunner.runOne("no crash".getBytes(StandardCharsets.UTF_8));
      if (i == 1) {
        // Initializing FuzzTargetRunner, which happens implicitly on the first call to runOne,
        // starts the Jazzer agent, which prints out some info messages to stdout. Ignore them.
        recordedOut.reset();
      }

      assert result == 0;
      assert fuzzerInitializeRan;
      assert CoverageMap.getCoveredIds().equals(Stream.of(0).collect(Collectors.toSet()));
      assert UNSAFE.getByte(CoverageMap.countersAddress) == i;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 1) == 0;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 2) == 0;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 3) == 0;

      String errOutput = new String(recordedErr.toByteArray(), StandardCharsets.UTF_8);
      List<String> unexpectedLines =
          Arrays.stream(errOutput.split("\n"))
              .filter(line -> !line.startsWith("INFO: "))
              .collect(Collectors.toList());
      assert unexpectedLines.isEmpty()
          : "Unexpected output on System.err: '" + String.join("\n", unexpectedLines) + "'";
      String outOutput = new String(recordedOut.toByteArray(), StandardCharsets.UTF_8);
      assert outOutput.isEmpty() : "Non-empty System.out: '" + outOutput + "'";
    }

    String firstDedupToken = null;
    for (int i = 1; i < 3; i++) {
      int result = FuzzTargetRunner.runOne("first finding".getBytes(StandardCharsets.UTF_8));

      assert result == 0;
      assert CoverageMap.getCoveredIds().equals(Stream.of(0, 1).collect(Collectors.toSet()));
      assert UNSAFE.getByte(CoverageMap.countersAddress) == 2;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 1) == i;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 2) == 0;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 3) == 0;

      String errOutput = new String(recordedErr.toByteArray(), StandardCharsets.UTF_8);
      String outOutput = new String(recordedOut.toByteArray(), StandardCharsets.UTF_8);
      if (i == 1) {
        assert errOutput.contains(
            "== Java Exception: java.lang.IllegalArgumentException: first finding");
        Matcher dedupTokenMatcher = DEDUP_TOKEN_PATTERN.matcher(outOutput);
        assert dedupTokenMatcher.matches() : "Unexpected output on System.out: '" + outOutput + "'";
        firstDedupToken = dedupTokenMatcher.group();
        recordedErr.reset();
        recordedOut.reset();
      } else {
        assert errOutput.isEmpty();
        assert outOutput.isEmpty();
      }
    }

    for (int i = 1; i < 3; i++) {
      int result = FuzzTargetRunner.runOne("second finding".getBytes(StandardCharsets.UTF_8));

      assert result == 0;
      assert CoverageMap.getCoveredIds().equals(Stream.of(0, 1, 2).collect(Collectors.toSet()));
      assert UNSAFE.getByte(CoverageMap.countersAddress) == 2;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 1) == 2;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 2) == i;
      assert UNSAFE.getByte(CoverageMap.countersAddress + 3) == 0;

      String errOutput = new String(recordedErr.toByteArray(), StandardCharsets.UTF_8);
      String outOutput = new String(recordedOut.toByteArray(), StandardCharsets.UTF_8);
      if (i == 1) {
        // Verify that the StackOverflowError is wrapped in security issue and contains reproducer
        // information.
        assert errOutput.contains(
            "== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow: Stack"
                + " overflow (use ");
        assert !errOutput.contains("not reported");
        Matcher dedupTokenMatcher = DEDUP_TOKEN_PATTERN.matcher(outOutput);
        assert dedupTokenMatcher.matches() : "Unexpected output on System.out: '" + outOutput + "'";
        assert !firstDedupToken.equals(dedupTokenMatcher.group());
        recordedErr.reset();
        recordedOut.reset();
      } else {
        assert errOutput.isEmpty();
        assert outOutput.isEmpty();
      }
    }

    finishedAllNonCrashingRuns = true;

    FuzzTargetRunner.runOne("crash".getBytes(StandardCharsets.UTF_8));

    throw new IllegalStateException("Expected FuzzTargetRunner to call fuzzerTearDown");
  }

  /** An OutputStream that prints to two OutputStreams simultaneously. */
  private static class TeeOutputStream extends PrintStream {
    private final PrintStream otherOut;

    public TeeOutputStream(PrintStream out1, PrintStream out2) {
      super(out1, true);
      this.otherOut = out2;
    }

    @Override
    public void flush() {
      super.flush();
      otherOut.flush();
    }

    @Override
    public void close() {
      super.close();
      otherOut.close();
    }

    @Override
    public void write(int b) {
      super.write(b);
      otherOut.write(b);
    }

    @Override
    public void write(byte[] buf, int off, int len) {
      super.write(buf, off, len);
      otherOut.write(buf, off, len);
    }
  }
}
