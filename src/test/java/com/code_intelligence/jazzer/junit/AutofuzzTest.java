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
import static org.junit.platform.testkit.engine.EventConditions.abortedWithReason;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.displayName;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.finishedWithFailure;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.EventConditions.uniqueIdSubstrings;
import static org.junit.platform.testkit.engine.EventType.DYNAMIC_TEST_REGISTERED;
import static org.junit.platform.testkit.engine.EventType.FINISHED;
import static org.junit.platform.testkit.engine.EventType.REPORTING_ENTRY_PUBLISHED;
import static org.junit.platform.testkit.engine.EventType.STARTED;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;
import org.opentest4j.TestAbortedException;

public class AutofuzzTest {
  @Rule public TemporaryFolder temp = new TemporaryFolder();

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    Path baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure to verify that Jazzer uses it and emits a
    // crash file into it.
    Path testResourceDir = baseDir.resolve("src").resolve("test").resolve("resources");
    Files.createDirectories(testResourceDir);
    Path inputsDirectory = testResourceDir.resolve("com")
                               .resolve("example")
                               .resolve("AutofuzzFuzzTestInputs")
                               .resolve("autofuzz");

    EngineExecutionResults results =
        EngineTestKit.engine("junit-jupiter")
            .selectors(selectMethod(
                "com.example.AutofuzzFuzzTest#autofuzz(java.lang.String,com.example.AutofuzzFuzzTest$IntHolder)"))
            .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
            .execute();

    final String engine = "engine:junit-jupiter";
    final String clazz = "class:com.example.AutofuzzFuzzTest";
    final String autofuzz =
        "test-template:autofuzz(java.lang.String, com.example.AutofuzzFuzzTest$IntHolder)";
    final String invocation = "test-template-invocation:#";

    results.containerEvents().assertEventsMatchExactly(event(type(STARTED), container(engine)),
        event(type(STARTED), container(uniqueIdSubstrings(engine, clazz))),
        event(type(STARTED), container(uniqueIdSubstrings(engine, clazz, autofuzz))),
        event(type(FINISHED), container(uniqueIdSubstrings(engine, clazz, autofuzz)),
            finishedSuccessfully()),
        event(type(FINISHED), container(uniqueIdSubstrings(engine, clazz)), finishedSuccessfully()),
        event(type(FINISHED), container(engine), finishedSuccessfully()));

    results.testEvents().assertEventsMatchExactly(event(type(DYNAMIC_TEST_REGISTERED)),
        event(type(STARTED)),
        event(test(uniqueIdSubstrings(engine, clazz, autofuzz, invocation + 1)),
            displayName("<empty input>"),
            abortedWithReason(instanceOf(TestAbortedException.class))),
        event(type(DYNAMIC_TEST_REGISTERED), test(uniqueIdSubstrings(engine, clazz, autofuzz))),
        event(type(STARTED), test(uniqueIdSubstrings(engine, clazz, autofuzz, invocation + 2)),
            displayName("Fuzzing...")),
        event(type(FINISHED), test(uniqueIdSubstrings(engine, clazz, autofuzz, invocation + 2)),
            displayName("Fuzzing..."), finishedWithFailure(instanceOf(RuntimeException.class))));

    // Should crash on an input that contains "jazzer", with the crash emitted into the
    // automatically created inputs directory.
    Path crashingInput;
    try (Stream<Path> crashFiles =
             Files.list(inputsDirectory)
                 .filter(path -> path.getFileName().toString().startsWith("crash-"))) {
      List<Path> crashFilesList = crashFiles.collect(Collectors.toList());
      assertWithMessage("Expected crashing input in " + baseDir).that(crashFilesList).hasSize(1);
      crashingInput = crashFilesList.get(0);
    }
    assertThat(new String(Files.readAllBytes(crashingInput), StandardCharsets.UTF_8))
        .contains("jazzer");

    try (Stream<Path> seeds = Files.list(baseDir).filter(Files::isRegularFile)) {
      assertThat(seeds).isEmpty();
    }

    // Verify that the engine created the generated corpus directory. Since the crash was not found
    // on a seed, it should not be empty.
    Path generatedCorpus =
        baseDir.resolve(".cifuzz-corpus").resolve("com.example.AutofuzzFuzzTest");
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
                "com.example.AutofuzzWithCorpusFuzzTest#autofuzzWithCorpus(java.lang.String,int)"))
            .execute();

    final String engine = "engine:junit-jupiter";
    final String clazz = "class:com.example.AutofuzzWithCorpusFuzzTest";
    final String autofuzzWithCorpus = "test-template:autofuzzWithCorpus(java.lang.String, int)";

    results.containerEvents().assertEventsMatchExactly(event(type(STARTED), container(engine)),
        event(type(STARTED), container(uniqueIdSubstrings(engine, clazz))),
        event(type(STARTED), container(uniqueIdSubstrings(engine, clazz, autofuzzWithCorpus))),
        // "No fuzzing has been performed..."
        event(type(REPORTING_ENTRY_PUBLISHED),
            container(uniqueIdSubstrings(engine, clazz, autofuzzWithCorpus))),
        event(type(FINISHED), container(uniqueIdSubstrings(engine, clazz, autofuzzWithCorpus)),
            finishedSuccessfully()),
        event(type(FINISHED), container(uniqueIdSubstrings(engine, clazz)), finishedSuccessfully()),
        event(type(FINISHED), container(engine), finishedSuccessfully()));

    results.testEvents().assertEventsMatchExactly(event(type(DYNAMIC_TEST_REGISTERED)),
        event(type(STARTED)),
        event(test("autofuzzWithCorpus", "<empty input>"), finishedSuccessfully()),
        event(type(DYNAMIC_TEST_REGISTERED)), event(type(STARTED)),
        event(test("autofuzzWithCorpus", "crashing_input"),
            finishedWithFailure(instanceOf(RuntimeException.class))));
  }
}
