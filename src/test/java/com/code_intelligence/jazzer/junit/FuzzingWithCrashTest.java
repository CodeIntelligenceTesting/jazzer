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

package com.code_intelligence.jazzer.junit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
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
import static org.junit.platform.testkit.engine.EventType.SKIPPED;
import static org.junit.platform.testkit.engine.EventType.STARTED;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.cause;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.launcher.TagFilter;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;
import org.opentest4j.AssertionFailedError;

public class FuzzingWithCrashTest {
  private static final String CRASHING_SEED_NAME = "crashing_seed";
  // Crashes ByteFuzzTest since 'b' % 2 == 0.
  private static final byte[] CRASHING_SEED_CONTENT = new byte[] {'b', 'a', 'c'};
  private static final String CRASHING_SEED_DIGEST = "5e4dec23c9afa48bd5bee3daa2a0ab66e147012b";
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String INVOCATION = "test-template-invocation:#";

  private static final String CLAZZ_NAME = "com.example.ValidFuzzTests";

  private static final String CLAZZ = "class:" + CLAZZ_NAME;
  private static final TestMethod BYTE_FUZZ = new TestMethod(CLAZZ_NAME, "byteFuzz([B)");
  private static final TestMethod NO_CRASH_FUZZ = new TestMethod(CLAZZ_NAME, "noCrashFuzz([B)");
  private static final TestMethod DATA_FUZZ =
      new TestMethod(CLAZZ_NAME, "dataFuzz(com.code_intelligence.jazzer.api.FuzzedDataProvider)");

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;
  Path inputsDirectory;

  @Before
  public void setup() throws IOException {
    baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure with an inputs directory to verify that
    // Jazzer uses it and emits a crash file into it.
    inputsDirectory =
        baseDir.resolve(
            Paths.get("src", "test", "resources", "com", "example", "ValidFuzzTestsInputs"));
    // populate the same seed in all test directories
    for (String method :
        Arrays.asList(BYTE_FUZZ.getName(), NO_CRASH_FUZZ.getName(), DATA_FUZZ.getName())) {
      Path methodInputsDirectory = inputsDirectory.resolve(method);
      Files.createDirectories(methodInputsDirectory);
      Files.write(methodInputsDirectory.resolve(CRASHING_SEED_NAME), CRASHING_SEED_CONTENT);
    }
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectClass("com.example.ValidFuzzTests"))
        .filters(TagFilter.includeTags("jazzer"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(
                type(STARTED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId())),
                finishedSuccessfully()),
            event(
                type(SKIPPED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ.getDescriptorId()))),
            event(
                type(SKIPPED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, DATA_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchLooselyInOrder(
            event(
                type(DYNAMIC_TEST_REGISTERED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId()))),
            event(
                type(STARTED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("Fuzzing...")),
            event(
                type(FINISHED),
                test(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId(), INVOCATION)),
                displayName("Fuzzing..."),
                finishedWithFailure(
                    instanceOf(FuzzTestFindingException.class),
                    cause(instanceOf(AssertionFailedError.class)))));

    // Jazzer first tries the empty input, which doesn't crash the ByteFuzzTest. The second input is
    // the seed we planted, which is crashing, so verify that a crash file with the same content is
    // created in our fake seed corpus, but not in the current working directory.
    try (Stream<Path> crashFiles =
        Files.list(baseDir).filter(path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }

    // the crashing input will be created in the directory for the fuzzed test, in this case
    // byteFuzz and will not exist in the directories of the other tests
    Path byteFuzzInputDirectory = inputsDirectory.resolve(BYTE_FUZZ.getName());
    try (Stream<Path> seeds = Files.list(byteFuzzInputDirectory)) {
      assertThat(seeds)
          .containsExactly(
              byteFuzzInputDirectory.resolve("crash-" + CRASHING_SEED_DIGEST),
              byteFuzzInputDirectory.resolve(CRASHING_SEED_NAME));
    }
    assertThat(Files.readAllBytes(byteFuzzInputDirectory.resolve("crash-" + CRASHING_SEED_DIGEST)))
        .isEqualTo(CRASHING_SEED_CONTENT);

    // check that the others only include 1 file
    for (String method : Arrays.asList(NO_CRASH_FUZZ.getName(), DATA_FUZZ.getName())) {
      Path methodInputsDirectory = inputsDirectory.resolve(method);
      try (Stream<Path> seeds = Files.list(methodInputsDirectory)) {
        assertThat(seeds).containsExactly(methodInputsDirectory.resolve(CRASHING_SEED_NAME));
      }
    }

    // Verify that the engine created the generated corpus directory. As a seed produced the crash,
    // it should be empty.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", CLAZZ_NAME, BYTE_FUZZ.getName()));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isEmpty();
    }
  }

  @Test
  public void fuzzingDisabled() throws IOException {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(
                type(STARTED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId()))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, BYTE_FUZZ.getDescriptorId())),
                finishedSuccessfully()),
            event(
                type(STARTED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ.getDescriptorId()))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, NO_CRASH_FUZZ.getDescriptorId()))),
            event(
                type(STARTED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, DATA_FUZZ.getDescriptorId()))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, DATA_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, DATA_FUZZ.getDescriptorId()))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    // No fuzzing means no crashes means no new seeds.
    // Check against all methods' input directories
    for (String method :
        Arrays.asList(BYTE_FUZZ.getName(), NO_CRASH_FUZZ.getName(), DATA_FUZZ.getName())) {
      Path methodInputsDirectory = inputsDirectory.resolve(method);
      try (Stream<Path> seeds = Files.list(methodInputsDirectory)) {
        assertThat(seeds).containsExactly(methodInputsDirectory.resolve(CRASHING_SEED_NAME));
      }
    }
  }
}
