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

import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;
import static org.junit.platform.testkit.engine.EventConditions.container;
import static org.junit.platform.testkit.engine.EventConditions.event;
import static org.junit.platform.testkit.engine.EventConditions.finishedSuccessfully;
import static org.junit.platform.testkit.engine.EventConditions.finishedWithFailure;
import static org.junit.platform.testkit.engine.EventConditions.skippedWithReason;
import static org.junit.platform.testkit.engine.EventConditions.test;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.instanceOf;
import static org.junit.platform.testkit.engine.TestExecutionResultConditions.message;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import org.junit.Test;
import org.junit.platform.testkit.engine.EngineExecutionResults;
import org.junit.platform.testkit.engine.EngineTestKit;
import org.opentest4j.AssertionFailedError;

public class RegressionTestTest {
  private static EngineExecutionResults executeTests() {
    return EngineTestKit.engine("junit-jupiter")
        .selectors(selectPackage("com.example"))
        .configurationParameter(
            "jazzer.instrument", "com.other.package.**,com.example.**,com.yet.another.package.*")
        .execute();
  }

  @Test
  public void regressionTestEnabled() {
    assumeTrue(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    results.testEvents().debug().assertEventsMatchLoosely(
        event(test("dataFuzz", "<empty input>"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueMedium.class))),
        event(test("dataFuzz", "no_crash"), finishedSuccessfully()),
        event(test("dataFuzz", "assert"),
            finishedWithFailure(instanceOf(AssertionFailedError.class))),
        event(test("dataFuzz", "honeypot"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueHigh.class))),
        event(test("dataFuzz", "sanitizer_internal_class"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueCritical.class))),
        event(test("dataFuzz", "sanitizer_user_class"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueLow.class))),
        event(test("byteFuzz", "<empty input>"),
            finishedWithFailure(instanceOf(FuzzerSecurityIssueMedium.class))),
        event(test("byteFuzz", "succeeds"), finishedSuccessfully()),
        event(test("byteFuzz", "fails"),
            finishedWithFailure(instanceOf(AssertionFailedError.class))));
    results.containerEvents().debug().assertEventsMatchLoosely(
        event(container("invalidParameterCountFuzz"),
            finishedWithFailure(instanceOf(IllegalArgumentException.class),
                message(
                    "Methods annotated with @FuzzTest must take a single byte[] or FuzzedDataProvider parameter"))),
        event(container("invalidParameterTypeFuzz"),
            finishedWithFailure(instanceOf(IllegalArgumentException.class),
                message(
                    "Methods annotated with @FuzzTest must take a single byte[] or FuzzedDataProvider parameter"))));
  }

  @Test
  public void regressionTestDisabled() {
    assumeFalse(System.getenv("JAZZER_FUZZ").isEmpty());

    EngineExecutionResults results = executeTests();

    // When fuzzing is requested, all regression tests are disabled.
    results.testEvents().debug().assertEventsMatchExactly();
    results.containerEvents().debug().assertEventsMatchLoosely(
        event(container("dataFuzz"),
            skippedWithReason(r -> r.contains("Regression tests are disabled"))),
        event(container("byteFuzz"),
            skippedWithReason(r -> r.contains("Regression tests are disabled"))),
        event(container("invalidParameterCountFuzz"),
            skippedWithReason(r -> r.contains("Regression tests are disabled"))),
        event(container("invalidParameterTypeFuzz"),
            skippedWithReason(r -> r.contains("Regression tests are disabled"))));
  }
}
