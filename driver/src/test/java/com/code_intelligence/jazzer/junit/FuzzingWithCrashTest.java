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

import java.io.IOException;
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
import org.opentest4j.AssertionFailedError;

public class FuzzingWithCrashTest {
  private static final String CRASHING_SEED_NAME = "crashing_seed";
  // Crashes ByteFuzzTest since 'b' % 2 == 0.
  private static final byte[] CRASHING_SEED_CONTENT = new byte[] {'b', 'a', 'c'};
  private static final String CRASHING_SEED_DIGEST = "5e4dec23c9afa48bd5bee3daa2a0ab66e147012b";

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;
  Path seedCorpus;

  @Before
  public void setup() throws IOException {
    baseDir = temp.getRoot().toPath();
    // Create a fake test resource directory structure with a seed corpus directory to verify that
    // Jazzer uses it and emits a crash file into it.
    seedCorpus = baseDir.resolve(
        Paths.get("src", "test", "resources", "com", "example", "ValidFuzzTestsSeedCorpus"));
    Files.createDirectories(seedCorpus);
    Files.write(seedCorpus.resolve(CRASHING_SEED_NAME), CRASHING_SEED_CONTENT);
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("com.code_intelligence.jazzer")
        .selectors(selectClass("com.example.ValidFuzzTests"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void fuzzingEnabled() throws IOException {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results.testEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED),
            test("com.example.ValidFuzzTests", "byteFuzz(byte[]) (Fuzzing)")),
        event(type(EventType.FINISHED),
            test("com.example.ValidFuzzTests", "byteFuzz(byte[]) (Fuzzing)"),
            finishedWithFailure(instanceOf(AssertionFailedError.class))),
        event(type(EventType.SKIPPED),
            test("com.example.ValidFuzzTests", "noCrashFuzz(byte[]) (Fuzzing)")),
        event(type(EventType.SKIPPED),
            test("com.example.ValidFuzzTests", "dataFuzz(FuzzedDataProvider) (Fuzzing)")));
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer")));

    // Jazzer first tries the empty input, which doesn't crash the ByteFuzzTest. The second input is
    // the seed we planted, which is crashing, so verify that a crash file with the same content is
    // created in our fake seed corpus, but not in the current working directory.
    try (Stream<Path> crashFiles = Files.list(baseDir).filter(
             path -> path.getFileName().toString().startsWith("crash-"))) {
      assertThat(crashFiles).isEmpty();
    }
    try (Stream<Path> seeds = Files.list(seedCorpus)) {
      assertThat(seeds).containsExactly(seedCorpus.resolve("crash-" + CRASHING_SEED_DIGEST),
          seedCorpus.resolve(CRASHING_SEED_NAME));
    }
    assertThat(Files.readAllBytes(seedCorpus.resolve("crash-" + CRASHING_SEED_DIGEST)))
        .isEqualTo(CRASHING_SEED_CONTENT);

    // Verify that the engine created the generated corpus directory. As a seed produced the crash,
    // it should be empty.
    Path generatedCorpus =
        baseDir.resolve(Paths.get(".cifuzz-corpus", "com.example.ValidFuzzTests"));
    assertThat(Files.isDirectory(generatedCorpus)).isTrue();
    try (Stream<Path> entries = Files.list(generatedCorpus)) {
      assertThat(entries).isEmpty();
    }
  }

  @Test
  public void fuzzingDisabled() throws IOException {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    // When fuzzing isn't requested, the Jazzer test engine doesn't discover any tests.
    results.testEvents().debug().assertEventsMatchExactly();
    results.containerEvents().debug().assertEventsMatchExactly(
        event(type(EventType.STARTED), container("com.code_intelligence.jazzer")),
        event(type(EventType.FINISHED), container("com.code_intelligence.jazzer"),
            finishedSuccessfully()));
    // No fuzzing means no crashes means no new seeds.
    try (Stream<Path> seeds = Files.list(seedCorpus)) {
      assertThat(seeds).containsExactly(seedCorpus.resolve(CRASHING_SEED_NAME));
    }
  }
}
