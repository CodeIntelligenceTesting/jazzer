/*
 * Copyright 2026 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.GlobTestSupport.mockSourceDirectory;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class GlobUtilsTest {

  static Path tempDir;

  @BeforeAll
  static void prepareTestFile(@TempDir Path tempDir) throws IOException {
    mockSourceDirectory(tempDir);
    GlobUtilsTest.tempDir = tempDir;
  }

  @Test
  void collectPathsForGlob_OneFile_AbsRel() {
    testCollectPathsForGlob_AbsRel(tempDir, "sub/deep/c.json", "sub/deep/c.json");
  }

  @Test
  void collectPathsForGlob_AbsoluteRelativePattern() {
    testCollectPathsForGlob_AbsRel(
        tempDir,
        "**.json",
        "sub/b.json",
        "sub/deep/c.json",
        "sub/deeper/than/foo.json",
        "test/c/d/foo.json");
  }

  @Test
  void collectPathsForGlob_SubDirectory() {
    testCollectPathsForGlob_AbsRel(
        tempDir, "sub/deep/**.txt", "sub/deep/c.txt", "sub/deep/corpus/d.txt");
  }

  @Test
  void collectPathsForGlob_AnySubdir() {
    testCollectPathsForGlob_AbsRel(
        tempDir,
        "sub/*/**.txt",
        "sub/deep/c.txt",
        "sub/deep/corpus/d.txt",
        "sub/deeper/than/mah.txt");
  }

  @Test
  void collectPathsForGlob_StartDirDoesNotExist() {
    testCollectPathsForGlob_AbsRel(
        tempDir, "nonexistent/**/*.json"
        // expects no matches
        );
  }

  @Test
  void collectPathsForGlob_AbsoluteRelative() {
    testCollectPathsForGlob_AbsRel(tempDir, "sub/deeper/than/fo*.json", "sub/deeper/than/foo.json");
  }

  @Test
  void collectPathsForGlob_PatternCharacters() {
    testCollectPathsForGlob_AbsRel(
        tempDir, "weird/*.glob", "weird/{}{braces}.glob", "weird/[]{}.glob");
  }

  static Stream<Arguments> patternCharactersEscape() {
    return new TestCaseBuilder()
        .withExpected("weird/[]{}.glob")
        .patterns("weird/\\[*.glob", "weird/\\[\\]*.glob", "weird/\\[\\]\\{\\}.glob")
        .build();
  }

  static Stream<Arguments> directoryHasEscapedChar() {
    return new TestCaseBuilder()
        .withExpected("escaped/[/test.escaped")
        .patterns(
            "escaped/**.escaped",
            "escaped/\\[/*.escaped",
            "escaped/\\[/**.escaped",
            "e*/\\[/*.escaped",
            "e**/\\[/*.escaped",
            "*/\\[/*.escaped")
        .build();
  }

  @Test
  void collectPathsForGlob_StarDetectionResets() {
    testCollectPathsForGlob_AbsRel(tempDir, "extra/*a*");
  }

  static Stream<Arguments> usefulPatterns() {
    return new TestCaseBuilder()
        .withExpected("a.txt", "b.zip")
        .patterns("?.???", "[ab].{txt,zip}", "{a.txt,b.zip}")
        .withExpected("sub/deep/c.json", "sub/deeper/than/foo.json")
        .patterns("sub/{deep,deeper/than}/*.json", "sub/**/{c,foo}.json")
        .withExpected(
            "sub/deep/c.txt",
            "sub/deep/c.json",
            "sub/deep/c.xml",
            "sub/deep/corpus/d.xml",
            "sub/deep/corpus/d.txt")
        .patterns(
            "sub/deep/**",
            "???/????/**.{json,txt,xml}",
            "sub/deep/**.{json,txt,xml}",
            "sub/dee?/**.{json,txt,xml}",
            "sub/?ee?/**.{json,txt,xml}")
        .withExpected("alpha-numeric/1a.numeric", "alpha-numeric/5h.numeric")
        .patterns("*/[0-5][a-h].numeric", "**/[0-5][a-h].numeric", "**/[!69][!IZ].numeric")
        .withExpected("alpha-numeric/6I.numeric", "alpha-numeric/9Z.numeric")
        .patterns("*/[6-9][I-Z].numeric", "**/[6-9][I-Z].numeric", "**/[6-9][I-Z].*")
        .build();
  }

  @ParameterizedTest
  @MethodSource({"directoryHasEscapedChar", "patternCharactersEscape", "usefulPatterns"})
  void test_provideCollectPathsForGlob_AllOperatingSystems(String glob, String[] expected) {
    testCollectPathsForGlob_AbsRel(tempDir, glob, expected);
  }

  static Stream<Arguments> EscapedPatternCharacters_Relative_NoWindows() {
    return new TestCaseBuilder()
        .withExpected("no-windows/asdf[sdf*df]f.glob")
        .patterns(
            "no-windows/asdf\\[*.glob", "no-windows/asdf\\[sdf\\**.glob", "no-windows/*f.glob")
        .withExpected("no-windows/hey?ho.glob")
        .patterns(
            "no-windows/he*.glob",
            "no-windows/hey\\?*.glob",
            "no-windows/hey\\?h*.glob",
            "no-windows/hey\\?h**",
            "no-windows/hey\\?ho.glob")
        .withExpected("no-windows/stars****stars.glob")
        .patterns(
            "no-windows/stars*.glob",
            "no-windows/stars\\**.glob",
            "no-windows/stars\\***.glob",
            "no-windows/stars\\*\\*\\*\\**.glob",
            "no-windows/stars\\*\\*\\*\\*?????.glob")
        .withExpected("no-windows/*?hello[there]{}.glob")
        .patterns(
            "no-windows/*there*.glob",
            "no-windows/\\*\\?*.glob",
            "no-windows/\\*\\?**.glob",
            "no-windows/\\*\\?hello*.glob",
            "no-windows/\\*\\?hello\\[*.glob",
            "no-windows/\\*\\?hello\\[**.glob",
            "no-windows/??hello\\[**.glob",
            "no-windows/[\\*]?hello\\[**.glob",
            "no-windows/[*]?hello\\[**.glob",
            "no-windows/[*][?]hello\\[**.glob",
            "no-windows/\\*\\?hello\\[there\\]\\{*.glob",
            "no-windows/\\*\\?hello\\[there\\]\\{\\}.glob")
        .withExpected("no-windows/backslash\\\\-es.glob")
        .patterns(
            "no-windows/back*.glob",
            "no-windows/backslash\\\\*-es.glob",
            "no-windows/backslash\\\\\\\\*-es.glob",
            "no-windows/backslash\\\\**.glob",
            "no-windows/backslash??-es.glob",
            "no-windows/backslash\\\\\\\\-es.glob")
        .build();
  }

  @DisabledOnOs(OS.WINDOWS)
  @ParameterizedTest
  @MethodSource("EscapedPatternCharacters_Relative_NoWindows")
  void test_provideCollectPathsForGlob_NoWindows(String glob, String[] expected) {
    testCollectPathsForGlob_AbsRel(tempDir, glob, expected);
  }

  static Stream<Arguments> windowsMixingDirSeparators() {
    return new TestCaseBuilder()
        .withExpected("sub/deep/corpus/d.xml")
        .patterns(
            "sub\\\\deep/corpus\\\\d.xml",
            "sub/deep\\\\corpus\\\\d.xml",
            "sub\\\\deep{/,t}corpus/d.xml")
        .build();
  }

  @EnabledOnOs(OS.WINDOWS)
  @ParameterizedTest
  @MethodSource("windowsMixingDirSeparators")
  void test_provideCollectPathsForGlob_Windows(String glob, String[] expected) {
    testCollectPathsForGlob_AbsRel(tempDir, glob, expected);
  }

  /**
   * Helper to test both relative and absolute glob patterns. This expects only relative patterns.
   * The absolute patterns are automatically constructed based on the provided tempDir and the
   * relative glob pattern.
   *
   * @param tempDir - base directory for glob matching
   * @param glob - relative-only glob pattern
   * @param expected - expected paths relative to tempDir
   */
  private static void testCollectPathsForGlob_AbsRel(
      Path tempDir, String glob, String... expected) {
    assertAll(
        () -> testGlob(tempDir, glob, expected),
        () -> testGlob(tempDir, tempDir + "/" + glob, expected));
  }

  private static void testGlob(Path tempDir, String glob, String... expected) {
    List<Path> matchedPaths =
        GlobUtils.collectPathsForGlob(tempDir, glob).stream()
            .map(Path::toAbsolutePath)
            .collect(Collectors.toList());

    List<Path> expectedPaths =
        Arrays.stream(expected)
            .map(tempDir::resolve)
            .map(Path::toAbsolutePath)
            .collect(Collectors.toList());

    assertThat(matchedPaths).containsExactlyElementsIn(expectedPaths);
  }

  private static class TestCaseBuilder {
    private final List<Arguments> arguments = new ArrayList<>();
    private String[] currentExpected;

    TestCaseBuilder withExpected(String... expected) {
      this.currentExpected = expected;
      return this;
    }

    TestCaseBuilder patterns(String... pattern) {
      for (String p : pattern) {
        arguments.add(Arguments.of(p, currentExpected));
      }
      return this;
    }

    Stream<Arguments> build() {
      return arguments.stream();
    }
  }
}
