// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.junit;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.finishedWithFailure;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.platform.testkit.engine.EventType;
import org.junit.rules.TemporaryFolder;

public class ValueProfileTest {
  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;
  Path seedCorpus;

  @Before
  public void setup() throws IOException {
    baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure with a seed corpus directory to verify that
    // Jazzer uses it and emits a crash file into it.
    seedCorpus = baseDir.resolve(
        Paths.get("src", "test", "resources", "com", "example", "ValueProfileFuzzTestSeedCorpus"));
    Files.createDirectories(seedCorpus);
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("com.code_intelligence.jazzer")
        .selectors(selectClass("com.example.ValueProfileFuzzTest"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.valueprofile", System.getenv("JAZZER_VALUE_PROFILE"))
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void valueProfileEnabled() throws IOException {
    assumeTrue("true".equals(System.getenv("JAZZER_VALUE_PROFILE")));

    EngineExecutionResults results = executeTests();

    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED),
            test("com.example.ValueProfileFuzzTest", "valueProfileFuzz(byte[]) (Fuzzing)")),
        event(type(EventType.FINISHED),
            test("com.example.ValueProfileFuzzTest", "valueProfileFuzz(byte[]) (Fuzzing)"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueMedium.class))));
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer")));

    // Should crash on the exact input "Jazzer", with the crash emitted into the seed corpus.
    try (Stream<Path> crashFiles =
             Files.list(baseDir).filter(path -> path.getFileName().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
    try (Stream<Path> seeds = Files.list(seedCorpus)) {
      assertThat(seeds).containsExactly(
          seedCorpus.resolve("crash-131db69c7fadc408fe5031079dad3a441df09aff"));
    }
    assertThat(
        Files.readAllBytes(seedCorpus.resolve("crash-131db69c7fadc408fe5031079dad3a441df09aff")))
        .isEqualTo("Jazzer".getBytes(StandardCharsets.UTF_8));

    // Verify that the engine created the generated corpus directory and emitted inputs into it.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValueProfileFuzzTest"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isNotEmpty();
    }
  }

  @Test
  public void valueProfileDisabled() throws IOException {
    assumeTrue("false".equals(System.getenv("JAZZER_VALUE_PROFILE")));

    EngineExecutionResults results = executeTests();

    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED),
            test("com.example.ValueProfileFuzzTest", "valueProfileFuzz(byte[]) (Fuzzing)")),
        event(type(EventType.FINISHED),
            test("com.example.ValueProfileFuzzTest", "valueProfileFuzz(byte[]) (Fuzzing)"),
            finishedSuccessfully()));
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer")));

    // No crash means no crashing input is emitted anywhere.
    try (Stream<Path> crashFiles =
             Files.list(baseDir).filter(path -> path.getFileName().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
    try (Stream<Path> seeds = Files.list(seedCorpus)) {
      assertThat(seeds).isEmpty();
    }

    // Verify that the engine created the generated corpus directory and emitted inputs into it.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValueProfileFuzzTest"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isNotEmpty();
    }
  }
}
