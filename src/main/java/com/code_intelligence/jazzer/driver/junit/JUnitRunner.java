/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.driver.junit;

import static com.code_intelligence.jazzer.driver.Constants.JAZZER_FINDING_EXIT_CODE;
import static com.code_intelligence.jazzer.driver.FuzzTargetRunner.printCrashingInput;
import static org.junit.platform.engine.FilterResult.includedIf;
import static org.junit.platform.engine.TestExecutionResult.Status.ABORTED;
import static org.junit.platform.engine.TestExecutionResult.Status.FAILED;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.launcher.TagFilter.includeTags;

import com.code_intelligence.jazzer.driver.ExceptionUtils;
import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.utils.Log;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.engine.JupiterTestEngine;
import org.junit.jupiter.engine.descriptor.MethodBasedTestDescriptor;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.PostDiscoveryFilter;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherConfig;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

public final class JUnitRunner {
  private final Launcher launcher;
  private final TestPlan testPlan;

  private JUnitRunner(Launcher launcher, TestPlan testPlan) {
    this.launcher = launcher;
    this.testPlan = testPlan;
  }

  // Detects the presence of both the JUnit launcher and the Jupiter engine on the classpath.
  public static boolean isSupported() {
    try {
      Class.forName("org.junit.platform.launcher.LauncherDiscoveryRequest");
      Class.forName("org.junit.jupiter.engine.JupiterTestEngine");
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  public static Optional<JUnitRunner> create(String testClassName, List<String> libFuzzerArgs) {
    // We want the test execution to be as lightweight as possible, so disable all auto-discover and
    // only register the test engine we are using for @FuzzTest, JUnit Jupiter.
    LauncherConfig config = LauncherConfig.builder()
                                .addTestEngines(new JupiterTestEngine())
                                .enableLauncherDiscoveryListenerAutoRegistration(false)
                                .enableLauncherSessionListenerAutoRegistration(false)
                                .enablePostDiscoveryFilterAutoRegistration(false)
                                .enableTestEngineAutoRegistration(false)
                                .enableTestExecutionListenerAutoRegistration(false)
                                .build();

    Map<String, String> indexedArgs =
        IntStream.range(0, libFuzzerArgs.size())
            .boxed()
            .collect(Collectors.toMap(i -> "jazzer.internal.arg." + i, libFuzzerArgs::get));

    LauncherDiscoveryRequestBuilder requestBuilder =
        LauncherDiscoveryRequestBuilder.request()
            .configurationParameter("jazzer.internal.commandLine", "true")
            .configurationParameters(indexedArgs)
            .selectors(selectClass(testClassName))
            .filters(includeTags("jazzer"));
    if (!Opt.targetMethod.isEmpty()) {
      // HACK: This depends on JUnit internals as we need to filter by method name without having to
      // specify the parameter types of the method.
      requestBuilder.filters((PostDiscoveryFilter) testDescriptor
          -> includedIf(!(testDescriptor instanceof MethodBasedTestDescriptor)
              || ((MethodBasedTestDescriptor) testDescriptor)
                     .getTestMethod()
                     .getName()
                     .equals(Opt.targetMethod)));
    }
    LauncherDiscoveryRequest request = requestBuilder.build();
    Launcher launcher = LauncherFactory.create(config);
    TestPlan testPlan = launcher.discover(request);
    if (!testPlan.containsTests()) {
      return Optional.empty();
    }
    return Optional.of(new JUnitRunner(launcher, testPlan));
  }

  public int run() {
    AtomicReference<TestExecutionResult> resultHolder =
        new AtomicReference<>(TestExecutionResult.successful());
    launcher.execute(testPlan, new TestExecutionListener() {
      @Override
      public void executionFinished(
          TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
        // Lifecycle methods can fail too, which results in failed execution results on container
        // nodes. We keep the last failing one with a stack trace. For tests, we also keep the stack
        // traces of aborted tests so that we can show a warning. In JUnit Jupiter, tests and
        // containers always fail with a throwable:
        // https://github.com/junit-team/junit5/blob/ac31e9a7d58973db73496244dab4defe17ae563e/junit-platform-engine/src/main/java/org/junit/platform/engine/support/hierarchical/ThrowableCollector.java#LL176C37-L176C37
        if ((testIdentifier.isTest() && testExecutionResult.getThrowable().isPresent())
            || testExecutionResult.getStatus() == FAILED) {
          resultHolder.set(testExecutionResult);
        }
        if (testExecutionResult.getStatus() == FAILED
            && testExecutionResult.getThrowable().isPresent()) {
          resultHolder.set(testExecutionResult);
        }
      }

      @Override
      public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
        entry.getKeyValuePairs().values().forEach(Log::info);
      }
    });

    TestExecutionResult result = resultHolder.get();
    if (result.getStatus() != FAILED) {
      // We do not generate a finding for Aborted tests (i.e. tests whose preconditions were not
      // met) as such tests also wouldn't make a test run fail.
      if (result.getStatus() == ABORTED) {
        Log.warn("Fuzz test aborted", result.getThrowable().orElse(null));
      }
      return 0;
    }

    // Safe to unwrap as result is either TestExecutionResult.successful() (initial value) or has
    // a throwable (set in the TestExecutionListener above).
    Throwable throwable = result.getThrowable().get();
    if (throwable instanceof ExitCodeException) {
      // Jazzer found a regular finding and printed it, so just return the exit code.
      return ((ExitCodeException) throwable).exitCode;
    } else {
      // Jazzer didn't report a finding, but an afterAll-type function threw an exception. Report it
      // as a finding, cleaning up the stack trace.
      Log.finding(ExceptionUtils.preprocessThrowable(throwable));
      Log.println("== libFuzzer crashing input ==");
      printCrashingInput();
      return JAZZER_FINDING_EXIT_CODE;
    }
  }
}
