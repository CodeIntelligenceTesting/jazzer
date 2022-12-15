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
import static org.junit.Assume.assumeFalse;
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
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.platform.testkit.engine.EventType;
import org.junit.rules.TemporaryFolder;

public class DirectoryInputsTest {
  @Rule public TemporaryFolder temp = new TemporaryFolder();

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    Path baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure with an inputs directory to verify that
    // Jazzer uses it and emits a crash file into it.
    Path inputsDirectory = baseDir.resolve(
        Paths.get("src", "test", "resources", "com", "example", "DirectoryInputsFuzzTestInputs"));
    Files.createDirectories(inputsDirectory);

    EngineExecutionResults results =
        EngineTestKit.engine("com.code_intelligence.jazzer")
            .selectors(selectClass("com.example.DirectoryInputsFuzzTest"))
            .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
            .execute();

    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer")));
    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED),
            test(
                "com.example.DirectoryInputsFuzzTest", "inputsFuzz(FuzzedDataProvider) (Fuzzing)")),
        event(type(EventType.FINISHED),
            test("com.example.DirectoryInputsFuzzTest", "inputsFuzz(FuzzedDataProvider) (Fuzzing)"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueMedium.class))));

    // Should crash on the exact input "directory" as provided by the seed, with the crash emitted
    // into the seed corpus.
    try (Stream<Path> crashFiles = Files.list(baseDir).filter(
             path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
    try (Stream<Path> seeds = Files.list(inputsDirectory)) {
      assertThat(seeds).containsExactly(
          inputsDirectory.resolve("crash-8d392f56d616a516ceabb82ed8906418bce4647d"));
    }
    assertThat(Files.readAllBytes(
                   inputsDirectory.resolve("crash-8d392f56d616a516ceabb82ed8906418bce4647d")))
        .isEqualTo("directory".getBytes(StandardCharsets.UTF_8));

    // Verify that the engine created the generated corpus directory. Since the crash was found on a
    // seed, it should be empty.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.DirectoryInputsFuzzTest"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isEmpty();
    }
  }

  @Test
  public void fuzzingDisabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results =
        EngineTestKit.engine("junit-jupiter")
            .selectors(selectClass("com.example.DirectoryInputsFuzzTest"))
            .execute();

    results.containerEvents().debug().assertEventsMatchLoosely(
        // "No fuzzing has been performed..."
        event(type(EventType.REPORTING_ENTRY_PUBLISHED), container("inputsFuzz")));
    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.DYNAMIC_TEST_REGISTERED)), event(type(EventType.STARTED)),
        event(test("inputsFuzz", "<empty input>"), finishedSuccessfully()),
        event(type(EventType.DYNAMIC_TEST_REGISTERED)), event(type(EventType.STARTED)),
        event(test("inputsFuzz", "seed"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueMedium.class))));
  }
}
