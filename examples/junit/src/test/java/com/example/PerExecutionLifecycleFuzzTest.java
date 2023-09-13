/*
 * Copyright 2022 Code Intelligence GmbH
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

package com.example;

import static com.google.common.truth.Truth.assertThat;
import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.junit.Lifecycle;
import com.example.PerExecutionLifecycleFuzzTest.LifecycleCallbacks1;
import com.example.PerExecutionLifecycleFuzzTest.LifecycleCallbacks2;
import com.example.PerExecutionLifecycleFuzzTest.LifecycleCallbacks3;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;

@TestMethodOrder(MethodOrderer.MethodName.class)
@ExtendWith(PerExecutionLifecycleFuzzTest.LifecycleInstancePostProcessor.class)
@ExtendWith(LifecycleCallbacks1.class)
@ExtendWith(LifecycleCallbacks2.class)
@ExtendWith(LifecycleCallbacks3.class)
class PerExecutionLifecycleFuzzTest {
  private static final ArrayList<String> events = new ArrayList<>();
  private static final long RUNS = 3;

  private boolean beforeEachCalledOnInstance = false;
  private boolean testInstancePostProcessorCalledOnInstance = false;

  @BeforeAll
  static void beforeAll() {
    events.add("beforeAll");
  }

  @BeforeEach
  void beforeEach1() {
    events.add("beforeEach1");
    beforeEachCalledOnInstance = true;
  }

  @BeforeEach
  void beforeEach2() {
    events.add("beforeEach2");
  }

  @BeforeEach
  void beforeEach3() {
    events.add("beforeEach3");
  }

  @Disabled
  @FuzzTest
  void disabledFuzz(byte[] data) {
    events.add("disabledFuzz");
    throw new AssertionError("This test should not be executed");
  }

  @FuzzTest(maxExecutions = RUNS, lifecycle = Lifecycle.PER_EXECUTION)
  void lifecycleFuzz(byte[] data) {
    events.add("lifecycleFuzz");
    assertThat(beforeEachCalledOnInstance).isTrue();
    assertThat(testInstancePostProcessorCalledOnInstance).isTrue();
  }

  @AfterEach
  void afterEach1() {
    events.add("afterEach1");
  }

  @AfterEach
  void afterEach2() {
    events.add("afterEach2");
  }

  @AfterEach
  void afterEach3() {
    events.add("afterEach3");
  }

  @AfterAll
  static void afterAll() throws TestSuccessfulException {
    events.add("afterAll");

    boolean isRegressionTest = "".equals(System.getenv("JAZZER_FUZZ"));
    boolean isFuzzingFromCommandLine = System.getenv("JAZZER_FUZZ") == null;
    boolean isFuzzingFromJUnit = !isFuzzingFromCommandLine && !isRegressionTest;

    final List<String> expectedBeforeEachEvents =
        unmodifiableList(
            asList(
                "beforeEachCallback1",
                "beforeEachCallback2",
                "beforeEachCallback3",
                "beforeEach1",
                "beforeEach2",
                "beforeEach3"));
    final List<String> expectedAfterEachEvents =
        unmodifiableList(
            asList(
                "afterEach1",
                "afterEach2",
                "afterEach3",
                "afterEachCallback3",
                "afterEachCallback2",
                "afterEachCallback1"));

    ArrayList<String> expectedEvents = new ArrayList<>();
    expectedEvents.add("beforeAll");

    // When run from the command-line, the fuzz test is not separately executed on the empty seed.
    if (isRegressionTest || isFuzzingFromJUnit) {
      expectedEvents.addAll(expectedBeforeEachEvents);
      expectedEvents.add("lifecycleFuzz");
      expectedEvents.addAll(expectedAfterEachEvents);
    }
    if (isFuzzingFromJUnit || isFuzzingFromCommandLine) {
      for (int i = 0; i < RUNS; i++) {
        expectedEvents.addAll(expectedBeforeEachEvents);
        expectedEvents.add("lifecycleFuzz");
        expectedEvents.addAll(expectedAfterEachEvents);
      }
    }

    expectedEvents.add("afterAll");

    assertThat(events).containsExactlyElementsIn(expectedEvents).inOrder();
    throw new TestSuccessfulException("Lifecycle methods invoked as expected");
  }

  static class LifecycleInstancePostProcessor implements TestInstancePostProcessor {
    @Override
    public void postProcessTestInstance(Object o, ExtensionContext extensionContext) {
      ((PerExecutionLifecycleFuzzTest) o).testInstancePostProcessorCalledOnInstance = true;
    }
  }

  static class LifecycleCallbacks1 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      events.add("beforeEachCallback1");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      events.add("afterEachCallback1");
    }
  }

  static class LifecycleCallbacks2 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      events.add("beforeEachCallback2");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      events.add("afterEachCallback2");
    }
  }

  static class LifecycleCallbacks3 implements BeforeEachCallback, AfterEachCallback {
    @Override
    public void beforeEach(ExtensionContext extensionContext) {
      events.add("beforeEachCallback3");
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
      events.add("afterEachCallback3");
    }
  }
}
