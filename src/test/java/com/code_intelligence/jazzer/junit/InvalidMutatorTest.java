/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.finishedWithFailure;
import static org.junit.platform.testkit.engine.EventConditions.type;
import static org.junit.platform.testkit.engine.EventConditions.uniqueIdSubstrings;
import static org.junit.platform.testkit.engine.EventType.FINISHED;
import static org.junit.platform.testkit.engine.EventType.STARTED;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.message;

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

public class InvalidMutatorTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String CLASS_NAME = "com.example.InvalidFuzzTests";
  private static final String METHOD_NAME = "invalidParameterResolverFuzz";
  private static final String PARAMETER_LIST =
      "com.code_intelligence.jazzer.api.FuzzedDataProvider, org.junit.jupiter.api.TestInfo";
  private static final String METHOD_SIGNATURE = METHOD_NAME + "(" + PARAMETER_LIST + ")";
  private static final String CLAZZ = "class:" + CLASS_NAME;
  private static final String LIFECYCLE_FUZZ = "test-template:" + METHOD_SIGNATURE;

  @Rule public TemporaryFolder temp = new TemporaryFolder();
  private Path baseDir;

  @Before
  public void setup() throws IOException {
    baseDir = temp.getRoot().toPath();
    Path inputsDirectory =
        baseDir.resolve(
            Paths.get(
                "src",
                "test",
                "resources",
                "com",
                "example",
                "InvalidFuzzTests",
                "invalidParameterResolverFuzz"));
    Files.createDirectories(inputsDirectory);
    Files.write(inputsDirectory.resolve("invalid"), "invalid input".getBytes());
  }

  private EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectMethod(CLASS_NAME + "#" + METHOD_SIGNATURE))
        .configurationParameter("jazzer.instrument", "com.example.**")
        .configurationParameter("jazzer.internal.basedir", baseDir.toAbsolutePath().toString())
        .execute();
  }

  @Test
  public void fuzzingEnabledAndDisabled() {
    executeTests()
        .containerEvents()
        .assertEventsMatchLoosely(
            event(type(STARTED), container(ENGINE)),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ))),
            event(type(STARTED), container(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ, LIFECYCLE_FUZZ)),
                finishedWithFailure(
                    message(
                        message ->
                            message.contains(
                                "Failed to construct mutator for"
                                    + " com.example.InvalidFuzzTests.invalidParameterResolverFuzz")))),
            event(
                type(FINISHED),
                container(uniqueIdSubstrings(ENGINE, CLAZZ)),
                finishedSuccessfully()),
            event(type(FINISHED), container(ENGINE), finishedSuccessfully()));
  }
}
