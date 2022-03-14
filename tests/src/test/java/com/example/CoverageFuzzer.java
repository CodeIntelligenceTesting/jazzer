/*
 * Copyright 2022 Code Intelligence GmbH
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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@SuppressWarnings({"unused", "UnusedReturnValue"})
public final class CoverageFuzzer {
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
    List<String> coverage = Files.readAllLines(Paths.get("./coverage.exec"));
    assertEquals(871, coverage.size());

    List<List<String>> sections = new ArrayList<>(4);
    sections.add(new ArrayList<>());
    coverage.forEach(l -> {
      if (l.isEmpty()) {
        sections.add(new ArrayList<>());
      }
      sections.get(sections.size() - 1).add(l);
    });

    List<String> branchCoverage = sections.get(0);
    assertEquals(217, branchCoverage.size());
    List<String> lineCoverage = sections.get(1);
    assertEquals(218, lineCoverage.size());
    List<String> incompleteCoverage = sections.get(2);
    assertEquals(218, incompleteCoverage.size());
    List<String> missedCoverage = sections.get(3);
    assertEquals(218, missedCoverage.size());

    String branch =
        branchCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find branch coverage"));
    //    assertEquals("CoverageFuzzer.java: 11/16 (68.75%)", branch);

    String line = lineCoverage.stream()
                      .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
                      .findFirst()
                      .orElseThrow(() -> new IllegalStateException("Could not find line coverage"));
    assertEquals("CoverageFuzzer.java: 15/61 (24.59%)", line);

    String incomplete =
        incompleteCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find incomplete coverage"));
    assertEquals("CoverageFuzzer.java: []", incomplete);

    String missed =
        missedCoverage.stream()
            .filter(l -> l.startsWith(CoverageFuzzer.class.getSimpleName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Could not find missed coverage"));
    if (IntStream.rangeClosed(15, 44).anyMatch(i -> missed.contains(String.valueOf(i)))) {
      throw new IllegalStateException("No coverage collected for ClassToCover");
    }

    // TODO switch to JaCoCo coverage report format
    //    CoverageBuilder coverage = new CoverageBuilder();
    //    ExecutionDataStore executionDataStore = new ExecutionDataStore();
    //    SessionInfoStore sessionInfoStore = new SessionInfoStore();
    //    try (FileInputStream bais = new FileInputStream("./coverage.exec")) {
    //      ExecutionDataReader reader = new ExecutionDataReader(bais);
    //      reader.setExecutionDataVisitor(executionDataStore);
    //      reader.setSessionInfoVisitor(sessionInfoStore);
    //      reader.read();
    //    }
    //    System.out.println(coverage.getClasses());
  }

  private static <T> void assertEquals(T expected, T actual) {
    if (!expected.equals(actual)) {
      throw new IllegalStateException(
          String.format("Expected \"%s\", got \"%s\"", expected, actual));
    }
  }
}
