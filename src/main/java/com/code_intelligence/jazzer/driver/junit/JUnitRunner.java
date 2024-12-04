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

package com.code_intelligence.jazzer.driver.junit;

import static com.code_intelligence.jazzer.driver.Constants.JAZZER_ERROR_EXIT_CODE;
import static com.code_intelligence.jazzer.driver.Constants.JAZZER_FINDING_EXIT_CODE;
import static com.code_intelligence.jazzer.driver.Constants.JAZZER_SUCCESS_EXIT_CODE;
import static org.junit.platform.engine.FilterResult.includedIf;
import static org.junit.platform.engine.TestExecutionResult.Status.ABORTED;
import static org.junit.platform.engine.TestExecutionResult.Status.FAILED;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.launcher.TagFilter.includeTags;

import com.code_intelligence.jazzer.driver.ExceptionUtils;
import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.junit.ExitCodeException;
import com.code_intelligence.jazzer.junit.FuzzTestConfigurationError;
import com.code_intelligence.jazzer.junit.FuzzTestFindingException;
import com.code_intelligence.jazzer.utils.Log;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
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
    LauncherConfig config =
        LauncherConfig.builder()
            .addTestEngines(new JupiterTestEngine())
            .enableLauncherDiscoveryListenerAutoRegistration(false)
            .enableLauncherSessionListenerAutoRegistration(false)
            .enablePostDiscoveryFilterAutoRegistration(false)
            .enableTestEngineAutoRegistration(false)
            .enableTestExecutionListenerAutoRegistration(false)
            .build();

    Map<String, String> indexedArgs =
        IntStream.range(JAZZER_SUCCESS_EXIT_CODE, libFuzzerArgs.size())
            .boxed()
            .collect(Collectors.toMap(i -> "jazzer.internal.arg." + i, libFuzzerArgs::get));

    // This class is only invoked via CLI, hence the timeout mode can be set solely based on the
    // fuzzing mode parameter.
    // The timeout mode is set to "disabled" in fuzzing mode, as libFuzzer handles timeouts.
    // In non-fuzzing mode, the timeout mode is set to "enabled" to ensure that JUnit handles
    // timeouts.
    String timeoutMode = Opt.isFuzzing.get() ? "disabled" : "enabled";
    Log.debug("JUnit timeout mode: " + timeoutMode);

    // If fuzzing is enabled, set the JAZZER_FUZZ environment variable to propagate the mode
    // to the JUnit integration, as that can't access Opt and the setting can not be
    // passed on easily in other ways.
    if (Opt.isFuzzing.get()) {
      System.setProperty("JAZZER_FUZZ", "true");
    }

    LauncherDiscoveryRequestBuilder requestBuilder =
        LauncherDiscoveryRequestBuilder.request()
            // JUnit's timeout handling interferes with libFuzzer as from the point of view of JUnit
            // all fuzz test invocations are combined in a single JUnit test method execution.
            // https://junit.org/junit5/docs/current/user-guide/#writing-tests-declarative-timeouts-mode
            .configurationParameter("junit.jupiter.execution.timeout.mode", timeoutMode)
            .configurationParameter("jazzer.internal.command_line", "true")
            .configurationParameters(indexedArgs)
            .selectors(selectClass(testClassName))
            .filters(includeTags("jazzer"));
    if (!Opt.targetMethod.get().isEmpty()) {
      // HACK: This depends on JUnit internals as we need to filter by method name without having to
      // specify the parameter types of the method.
      requestBuilder.filters(
          (PostDiscoveryFilter)
              testDescriptor ->
                  includedIf(
                      !(testDescriptor instanceof MethodBasedTestDescriptor)
                          || ((MethodBasedTestDescriptor) testDescriptor)
                              .getTestMethod()
                              .getName()
                              .equals(Opt.targetMethod.get())));
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
    AtomicReference<TestExecutionResult> testResultHolder = new AtomicReference<>();
    AtomicBoolean sawContainerFailure = new AtomicBoolean();
    launcher.execute(
        testPlan,
        new TestExecutionListener() {
          @Override
          public void testPlanExecutionStarted(TestPlan testPlan) {
            Log.debug("Fuzzing started for " + testPlan);
          }

          @Override
          public void executionStarted(TestIdentifier testIdentifier) {
            Log.debug("Fuzz test started: " + testIdentifier.getDisplayName());
          }

          @Override
          public void executionSkipped(TestIdentifier testIdentifier, String reason) {
            Log.debug(
                "Fuzz test skipped: " + testIdentifier.getDisplayName() + " (" + reason + ")");
          }

          @Override
          public void testPlanExecutionFinished(TestPlan testPlan) {
            Log.debug("Fuzzing finished for " + testPlan);
          }

          @Override
          public void executionFinished(
              TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
            if (testIdentifier.isTest()) {
              testResultHolder.set(testExecutionResult);
            } else {
              // Lifecycle methods can fail too, which results in failed execution results on
              // container nodes. We emit all these failures as errors, not findings, since the
              // lifecycle methods invoked by JUnit, which don't include @BeforeEach and
              // @AfterEach executed during individual fuzz test executions, usually aren't
              // reproducible with any given input (e.g. @AfterAll methods).
              testExecutionResult
                  .getThrowable()
                  .map(ExceptionUtils::preprocessThrowable)
                  .ifPresent(
                      throwable -> {
                        sawContainerFailure.set(true);
                        Log.error(throwable);
                      });
            }
          }

          @Override
          public void reportingEntryPublished(TestIdentifier testIdentifier, ReportEntry entry) {
            entry.getKeyValuePairs().values().forEach(Log::info);
          }
        });

    TestExecutionResult result = testResultHolder.get();
    Log.debug("Fuzz test result: " + result);
    if (result == null) {
      // This can only happen if a test container failed, in which case we will have printed a
      // stack trace.
      Log.error("Failed to run fuzz test");
      return JAZZER_ERROR_EXIT_CODE;
    }
    if (result.getStatus() != FAILED) {
      // We do not generate a finding for aborted tests (i.e. tests whose preconditions were not
      // met) as such tests also wouldn't make a test run fail.
      if (result.getStatus() == ABORTED) {
        Log.warn("Fuzz test aborted", result.getThrowable().orElse(null));
      }
      if (sawContainerFailure.get()) {
        // A failure in a test container indicates a setup error, so we don't return the finding
        // exit code in this case.
        return JAZZER_ERROR_EXIT_CODE;
      }
      return JAZZER_SUCCESS_EXIT_CODE;
    }

    // Safe to unwrap as in JUnit Jupiter, tests and containers always fail with a Throwable:
    // https://github.com/junit-team/junit5/blob/ac31e9a7d58973db73496244dab4defe17ae563e/junit-platform-engine/src/main/java/org/junit/platform/engine/support/hierarchical/ThrowableCollector.java#LL176C37-L176C37
    @SuppressWarnings("OptionalGetWithoutIsPresent")
    Throwable throwable = result.getThrowable().get();
    if (throwable instanceof FuzzTestFindingException) {
      // Non-fatal findings and exceptions in containers have already been printed, the fatal
      // finding is passed to JUnit as the test result.
      return JAZZER_FINDING_EXIT_CODE;
    } else if (throwable instanceof FuzzTestConfigurationError) {
      // Error configuring JUnit for fuzzing, e.g. due to unsupported fuzz test parameter.
      return JAZZER_ERROR_EXIT_CODE;
    } else if (throwable instanceof ExitCodeException) {
      // libFuzzer exited with a non-zero exit code, but Jazzer didn't produce a finding. Forward
      // the exit code and assume that information has already been printed (e.g. a timeout).
      return ((ExitCodeException) throwable).exitCode;
    } else {
      // None-finding exceptions are not already handled, so need to be printed here.
      Log.error(throwable);
      return JAZZER_ERROR_EXIT_CODE;
    }
  }
}
