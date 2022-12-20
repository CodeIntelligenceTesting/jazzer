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

import static com.google.common.truth.Truth8.assertThat;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;
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
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.message;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.opentest4j.AssertionFailedError;

public class RegressionTestTest {
  private static final String ENGINE = "engine:junit-jupiter";
  private static final String BYTE_FUZZ_TEST = "class:com.example.ByteFuzzTest";
  private static final String VALID_FUZZ_TESTS = "class:com.example.ValidFuzzTests";
  private static final String INVALID_FUZZ_TESTS = "class:com.example.InvalidFuzzTests";
  private static final String AUTOFUZZ_WITH_CORPUS_FUZZ_TEST =
      "class:com.example.AutofuzzWithCorpusFuzzTest";
  private static final String BYTE_FUZZ = "test-template:byteFuzz([B)";
  private static final String NO_CRASH_FUZZ = "test-template:noCrashFuzz([B)";
  private static final String DATA_FUZZ =
      "test-template:dataFuzz(com.code_intelligence.jazzer.api.FuzzedDataProvider)";
  private static final String INVALID_PARAMETER_COUNT_FUZZ =
      "test-template:invalidParameterCountFuzz()";
  private static final String AUTOFUZZ_WITH_CORPUS =
      "test-template:autofuzzWithCorpus(java.lang.String, int)";
  private static final String INVOCATION = "test-template-invocation:#";

  private static EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectPackage("com.example"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .execute();
  }

  @Test
  public void regressionTestEnabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ") == null);

    // Record Jazzer's stderr.
    PrintStream stderr = System.err;
    ByteArrayOutputStream recordedStderr = new ByteArrayOutputStream();
    System.setErr(new PrintStream(recordedStderr));

    EngineExecutionResults results = executeTests();
    System.setErr(stderr);

    // Verify that Jazzer doesn't print any warning or errors.
    String[] stderrLines =
        new String(recordedStderr.toByteArray(), StandardCharsets.UTF_8).split("\n");
    for (String line : stderrLines) {
      System.err.println(line);
    }
    assertThat(Arrays.stream(stderrLines)
                   .filter(line -> line.startsWith("WARN:") || line.startsWith("ERROR:")))
        .isEmpty();

    results.containerEvents().debug().assertEventsMatchLoosely(
        event(type(STARTED), container(ENGINE)),
        event(
            type(STARTED), container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, NO_CRASH_FUZZ))),
        event(type(REPORTING_ENTRY_PUBLISHED),
            container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, NO_CRASH_FUZZ))),
        event(type(FINISHED),
            container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, NO_CRASH_FUZZ)),
            finishedSuccessfully()),
        event(type(STARTED), container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ))),
        event(type(REPORTING_ENTRY_PUBLISHED),
            container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ))),
        event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ)),
            finishedSuccessfully()),
        event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS)),
            finishedSuccessfully()),
        event(type(STARTED), container(uniqueIdSubstrings(ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST))),
        event(type(STARTED),
            container(
                uniqueIdSubstrings(ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS))),
        event(type(REPORTING_ENTRY_PUBLISHED),
            container(
                uniqueIdSubstrings(ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS))),
        event(type(FINISHED),
            container(
                uniqueIdSubstrings(ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS)),
            finishedSuccessfully()),
        event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST)),
            finishedSuccessfully()),
        event(type(STARTED), container(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST))),
        event(type(STARTED), container(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ))),
        event(type(REPORTING_ENTRY_PUBLISHED),
            container(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ))),
        event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ)),
            finishedSuccessfully()),
        event(type(STARTED), container(uniqueIdSubstrings(ENGINE, INVALID_FUZZ_TESTS))),
        event(type(STARTED),
            container(
                uniqueIdSubstrings(ENGINE, INVALID_FUZZ_TESTS, INVALID_PARAMETER_COUNT_FUZZ))),
        event(type(FINISHED),
            container(uniqueIdSubstrings(ENGINE, INVALID_FUZZ_TESTS, INVALID_PARAMETER_COUNT_FUZZ)),
            finishedWithFailure(instanceOf(IllegalArgumentException.class),
                message("Methods annotated with @FuzzTest must take at least one parameter"))),
        event(type(FINISHED), container(uniqueIdSubstrings(ENGINE, INVALID_FUZZ_TESTS)),
            finishedSuccessfully()),
        event(type(FINISHED), container(ENGINE), finishedSuccessfully()));

    results.testEvents().debug().assertEventsMatchLoosely(
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("<empty input>")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("<empty input>")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("<empty input>"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueMedium.class))),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("no_crash")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("no_crash")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("no_crash"), finishedSuccessfully()),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("assert")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("assert")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("assert"), finishedWithFailure(instanceOf(AssertionFailedError.class))),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("honeypot")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("honeypot")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("honeypot"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueHigh.class))),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("sanitizer_internal_class")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("sanitizer_internal_class")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("sanitizer_internal_class"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueCritical.class))),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("sanitizer_user_class")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("sanitizer_user_class")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, VALID_FUZZ_TESTS, DATA_FUZZ, INVOCATION)),
            displayName("sanitizer_user_class"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueLow.class))),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("<empty input>")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("<empty input>")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("<empty input>"), finishedSuccessfully()),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("succeeds")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("succeeds")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("succeeds"), finishedSuccessfully()),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("fails")),
        event(type(STARTED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("fails")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(ENGINE, BYTE_FUZZ_TEST, BYTE_FUZZ, INVOCATION)),
            displayName("fails"), finishedWithFailure(instanceOf(AssertionFailedError.class))),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(
                ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS, INVOCATION)),
            displayName("<empty input>")),
        event(type(STARTED),
            test(uniqueIdSubstrings(
                ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS, INVOCATION)),
            displayName("<empty input>")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(
                ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS, INVOCATION)),
            displayName("<empty input>"), finishedSuccessfully()),
        event(type(DYNAMIC_TEST_REGISTERED),
            test(uniqueIdSubstrings(
                ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS, INVOCATION)),
            displayName("crashing_input")),
        event(type(STARTED),
            test(uniqueIdSubstrings(
                ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS, INVOCATION)),
            displayName("crashing_input")),
        event(type(FINISHED),
            test(uniqueIdSubstrings(
                ENGINE, AUTOFUZZ_WITH_CORPUS_FUZZ_TEST, AUTOFUZZ_WITH_CORPUS, INVOCATION)),
            displayName("crashing_input"),
            finishedWithFailure(instanceOf(RuntimeException.class))));
  }
}
