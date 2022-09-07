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
import static com.google.common.truth.Truth.assertWithMessage;
import static com.google.common.truth.Truth8.assertThat;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.finishedWithFailure;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.platform.testkit.engine.EventType;
import org.junit.rules.TemporaryFolder;

public class AutofuzzTest {
  @Rule public TemporaryFolder temp = new TemporaryFolder();

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    Path baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure with a seed corpus directory to verify that
    // Jazzer uses it and emits a crash file into it.
    Path seedCorpus = baseDir.resolve(
        Paths.get("src", "test", "resources", "com", "example", "AutofuzzFuzzTestsSeedCorpus"));
    Files.createDirectories(seedCorpus);

    EngineExecutionResults results =
        EngineTestKit.engine("com.code_intelligence.jazzer")
            .selectors(selectMethod(
                "com.example.AutofuzzFuzzTests#autofuzz(java.lang.String,com.example.AutofuzzFuzzTests$IntHolder)"))
            .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
            .execute();

    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED),
            test("com.example.AutofuzzFuzzTests", "autofuzz(String, IntHolder) (Fuzzing)")),
        // No seed corpus.
        event(type(EventType.REPORTING_ENTRY_PUBLISHED)),
        event(type(EventType.FINISHED),
            test("com.example.AutofuzzFuzzTests", "autofuzz(String, IntHolder) (Fuzzing)"),
            finishedWithFailure(instanceOf(RuntimeException.class))));
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer")));

    // Should crash on an input that starts with "jazzer", with the crash emitted into the base
    // directory since there is no seed corpus.
    Path crashingInput;
    try (Stream<Path> crashFiles = Files.list(baseDir).filter(
             path -> path.getFileName().toString().startsWith("crash-"))) {
      List<Path> crashFilesList = crashFiles.collect(Collectors.toList());
      assertWithMessage("Expected crashing input in " + baseDir).that(crashFilesList).hasSize(1);
      crashingInput = crashFilesList.get(0);
    }
    assertThat(new String(Files.readAllBytes(crashingInput), StandardCharsets.UTF_8))
        .startsWith("jazzer");

    try (Stream<Path> seeds = Files.list(seedCorpus)) {
      assertThat(seeds).isEmpty();
    }

    // Verify that the engine created the generated corpus directory. Since the crash was not found
    // on a seed, it should not be empty.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.AutofuzzFuzzTests"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isNotEmpty();
    }
  }

  @Test
  public void fuzzingDisabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results =
        EngineTestKit.engine("junit-jupiter")
            .selectors(selectMethod(
                "com.example.AutofuzzFuzzTests#autofuzzWithCorpus(java.lang.String,int)"))
            .execute();

    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.DYNAMIC_TEST_REGISTERED)), event(type(EventType.STARTED)),
        // "No fuzzing has been performed..."
        event(type(EventType.REPORTING_ENTRY_PUBLISHED)),
        event(test("autofuzzWithCorpus", "<empty input>"), finishedSuccessfully()),
        event(type(EventType.DYNAMIC_TEST_REGISTERED)), event(type(EventType.STARTED)),
        // "No fuzzing has been performed..."
        event(type(EventType.REPORTING_ENTRY_PUBLISHED)),
        event(test("autofuzzWithCorpus", "crashing_input"),
            finishedWithFailure(instanceOf(RuntimeException.class))));
  }
}
