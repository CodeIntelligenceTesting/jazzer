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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataReader;
import org.jacoco.core.data.ExecutionDataStore;
import org.jacoco.core.data.SessionInfoStore;

/**
 * Test of coverage report and dump.
 *
 * <p>Internally, JaCoCo is used to gather coverage information to guide the fuzzer to cover new
 * branches. This information can be dumped in the JaCoCo format and used to generate reports later
 * on. The dump only contains classes with at least one coverage data point. A JaCoCo report will
 * also include completely uncovered files based on the available classes in the stated jar files in
 * the report command.
 *
 * <p>A human-readable coverage report can be generated directly by Jazzer. It contains information
 * on file level about all classes that should have been instrumented according to the
 * instrumentation_includes and instrumentation_exclude filters.
 */
@SuppressWarnings({"unused", "UnusedReturnValue"})
public final class CoverageFuzzer {
  // Not used during fuzz run, so not included in the dump
  public static class ClassNotToCover {
    private final int i;

    public ClassNotToCover(int i) {
      this.i = i;
    }

    public int getI() {
      return i;
    }
  }

  // Used in the fuzz run and included in the dump
  public static class ClassToCover {
    private final int i;

    public ClassToCover(int i) {
      if (i < 0 || i > 1000) {
        throw new IllegalArgumentException(String.format("Invalid repeat number \"%d\"", i));
      }
      this.i = i;
    }

    public String repeat(String str) {
      if (str != null && str.length() >= 3 && str.length() <= 10) {
        return IntStream.range(0, i).mapToObj(i -> str).collect(Collectors.joining());
      }
      throw new IllegalArgumentException(String.format("Invalid str \"%s\"", str));
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      ClassToCover classToCover = new ClassToCover(data.consumeInt());
      String repeated = classToCover.repeat(data.consumeRemainingAsAsciiString());
      if (repeated.equals("foofoofoo")) {
        throw new FuzzerSecurityIssueLow("Finished coverage fuzzer test");
      }
    } catch (IllegalArgumentException ignored) {
    }
  }

  public static void fuzzerTearDown() throws IOException {
    assertCoverageReport();
    assertCoverageDump();
  }

  private static void assertCoverageReport() throws IOException {
    List<String> coverage = Files.readAllLines(Paths.get(System.getenv("COVERAGE_REPORT_FILE")));
    List<List<String>> sections = new ArrayList<>(4);
    sections.add(new ArrayList<>());
    coverage.forEach(
        l -> {
          if (l.isEmpty()) {
            sections.add(new ArrayList<>());
          } else {
            sections.get(sections.size() - 1).add(l);
          }
        });

    List<String> branchCoverage = sections.get(0);
    assertEquals(2, branchCoverage.size());
    List<String> lineCoverage = sections.get(1);
    assertEquals(2, lineCoverage.size());
    List<String> incompleteCoverage = sections.get(2);
    assertEquals(2, incompleteCoverage.size());
    List<String> missedCoverage = sections.get(3);
    assertEquals(2, missedCoverage.size());

    assertNotNull(
        branchCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find branch coverage")));

    assertNotNull(
        lineCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find line coverage")));

    assertNotNull(
        incompleteCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find incomplete coverage")));

    String missed =
        missedCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find missed coverage"));
    List<String> missingLines =
        IntStream.rangeClosed(63, 79)
            .mapToObj(i -> " " + i)
            .filter(missed::contains)
            .collect(Collectors.toList());
    if (!missingLines.isEmpty()) {
      throw new IllegalStateException(
          String.format(
              "Missing coverage for ClassToCover on lines %s", String.join(", ", missingLines)));
    }
  }

  private static void assertCoverageDump() throws IOException {
    ExecutionDataStore executionDataStore = new ExecutionDataStore();
    SessionInfoStore sessionInfoStore = new SessionInfoStore();
    try (FileInputStream bais = new FileInputStream(System.getenv("COVERAGE_DUMP_FILE"))) {
      ExecutionDataReader reader = new ExecutionDataReader(bais);
      reader.setExecutionDataVisitor(executionDataStore);
      reader.setSessionInfoVisitor(sessionInfoStore);
      reader.read();
    }
    assertEquals(2, executionDataStore.getContents().size());

    ExecutionData coverageFuzzerCoverage = new ExecutionData(0, "", 0);
    ExecutionData classToCoverCoverage = new ExecutionData(0, "", 0);
    for (ExecutionData content : executionDataStore.getContents()) {
      if (content.getName().endsWith("ClassToCover")) {
        classToCoverCoverage = content;
      } else {
        coverageFuzzerCoverage = content;
      }
    }

    assertEquals("com/example/CoverageFuzzer", coverageFuzzerCoverage.getName());
    assertEquals(7, countHits(coverageFuzzerCoverage.getProbes()));

    assertEquals("com/example/CoverageFuzzer$ClassToCover", classToCoverCoverage.getName());
    assertEquals(10, countHits(classToCoverCoverage.getProbes()));
  }

  private static int countHits(boolean[] probes) {
    int count = 0;
    for (boolean probe : probes) {
      if (probe) count++;
    }
    return count;
  }

  private static <T> void assertEquals(T expected, T actual) {
    if (!expected.equals(actual)) {
      throw new IllegalStateException(
          String.format("Expected \"%s\", got \"%s\"", expected, actual));
    }
  }

  private static <T> void assertNotNull(T actual) {
    if (actual == null) {
      throw new IllegalStateException("Expected none null value, got null");
    }
  }
}
