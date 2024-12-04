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

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.displayName;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.EventConditions.uniqueIdSubstrings;
import static org.junit.platform.testkit.engine.EventType.FINISHED;
import static org.junit.platform.testkit.engine.EventType.REPORTING_ENTRY_PUBLISHED;
import static org.junit.platform.testkit.engine.EventType.STARTED;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.junit.rules.TemporaryFolder;

public class CoverageTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLAZZ = "com.example.CoverageFuzzTest";
  private static final String CLAZZ_FUZZ = "class:" + CLAZZ;
  private static final String INPUTS_FUZZ = "test-template:coverage(long)";

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  Path baseDir;

  @Before
  public void setup() {
    baseDir = temp.getRoot().toPath();
  }

  @Test
  public void coverageRegressionRun() throws IOException {
    Path explicitGeneratedCorpus = baseDir.resolve(Paths.get("corpus"));
    Files.createDirectories(explicitGeneratedCorpus);
    Files.write(explicitGeneratedCorpus.resolve("4"), new byte[] {0, 0, 0, 0, 0, 0, 0, 4});

    Path additionalCorpus = baseDir.resolve(Paths.get("corpus2"));
    Files.createDirectories(additionalCorpus);
    Files.write(additionalCorpus.resolve("5"), new byte[] {0, 0, 0, 0, 0, 0, 0, 5});

    EngineExecutionResults results =
        EngineTestKit.engine("junit-jupiter")
            .selectors(selectClass(CLAZZ))
            .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
            .configurationParameter("jazzer.internal.arg.0", "fake_test_argv0")
            .configurationParameter(
                "jazzer.internal.arg.1", explicitGeneratedCorpus.toAbsolutePath().toString())
            .configurationParameter(
                "jazzer.internal.arg.2", additionalCorpus.toAbsolutePath().toString())
            .execute();

    results
        .containerEvents()
        .assertEventsMatchExactly(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ_FUZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ_FUZZ, INPUTS_FUZZ))),
            event(
                type(REPORTING_ENTRY_PUBLISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, INPUTS_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ_FUZZ, INPUTS_FUZZ)),
                finishedSuccessfully()),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ_FUZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results
        .testEvents()
        .assertEventsMatchLoosely(
            event(type(FINISHED), displayName("<empty input>"), finishedSuccessfully()),
            event(type(FINISHED), displayName("1"), finishedSuccessfully()),
            event(type(FINISHED), displayName("2"), finishedSuccessfully()),
            event(type(FINISHED), displayName("3"), finishedSuccessfully()),
            event(type(FINISHED), displayName("4"), finishedSuccessfully()),
            event(type(FINISHED), displayName("5"), finishedSuccessfully()));
  }
}
