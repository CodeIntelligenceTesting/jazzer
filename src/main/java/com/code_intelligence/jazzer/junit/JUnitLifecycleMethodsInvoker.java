/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.junit;

import static java.util.stream.Collectors.toCollection;

import com.code_intelligence.jazzer.driver.LifecycleMethodsInvoker;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.engine.execution.AfterEachMethodAdapter;
import org.junit.jupiter.engine.execution.BeforeEachMethodAdapter;
import org.junit.jupiter.engine.execution.DefaultExecutableInvoker;
import org.junit.jupiter.engine.extension.ExtensionRegistry;

/**
 * Adapts JUnit BeforeEach and AfterEach callbacks to
 * {@link com.code_intelligence.jazzer.driver.FuzzTargetRunner} lifecycle hooks.
 */
public class JUnitLifecycleMethodsInvoker implements LifecycleMethodsInvoker {
  private final ThrowingRunnable[] beforeEachExecutionRunnables;

  private long timesCalledBetweenExecutions = 0;

  private JUnitLifecycleMethodsInvoker(ThrowingRunnable[] beforeEachExecutionRunnables) {
    this.beforeEachExecutionRunnables = beforeEachExecutionRunnables;
  }

  static LifecycleMethodsInvoker of(ExtensionContext extensionContext) {
    // ExtensionRegistry is private JUnit API that is the source of truth for all lifecycle
    // callbacks, both annotation- and extension-based.
    Optional<ExtensionRegistry> maybeExtensionRegistry =
        getExtensionRegistryViaHack(extensionContext);
    if (!maybeExtensionRegistry.isPresent()) {
      extensionContext.publishReportEntry(
          "Jazzer does not support BeforeEach and AfterEach callbacks with this version of JUnit.");
      return LifecycleMethodsInvoker.NOOP;
    }
    ExtensionRegistry extensionRegistry = maybeExtensionRegistry.get();

    // BeforeEachCallback implementations take precedence over @BeforeEach methods. The annotations
    // are turned into extensions using an internal adapter class, BeforeEachMethodAdapter.
    // https://junit.org/junit5/docs/current/user-guide/#extensions-execution-order-wrapping-behavior
    ArrayList<ThrowingRunnable> beforeEachMethods =
        Stream
            .<ThrowingRunnable>concat(
                extensionRegistry.stream(BeforeEachCallback.class)
                    .map(callback -> () -> callback.beforeEach(extensionContext)),
                extensionRegistry.stream(BeforeEachMethodAdapter.class)
                    .map(callback
                        -> ()
                            -> callback.invokeBeforeEachMethod(
                                extensionContext, extensionRegistry)))
            .collect(toCollection(ArrayList::new));

    ArrayList<ThrowingRunnable> afterEachMethods =
        Stream
            .<ThrowingRunnable>concat(
                extensionRegistry.stream(AfterEachCallback.class)
                    .map(callback -> () -> callback.afterEach(extensionContext)),
                extensionRegistry.stream(AfterEachMethodAdapter.class)
                    .map(callback
                        -> ()
                            -> callback.invokeAfterEachMethod(extensionContext, extensionRegistry)))
            .collect(toCollection(ArrayList::new));
    // JUnit calls AfterEach methods in reverse order of registration so that the methods registered
    // first run last.
    Collections.reverse(afterEachMethods);

    return new JUnitLifecycleMethodsInvoker(
        Stream.concat(afterEachMethods.stream(), beforeEachMethods.stream())
            .toArray(ThrowingRunnable[] ::new));
  }

  private static Optional<ExtensionRegistry> getExtensionRegistryViaHack(
      ExtensionContext extensionContext) {
    // Do not fail on JUnit versions < 5.9.0 that do not have DefaultExecutableInvoker.
    try {
      Class.forName("org.junit.jupiter.engine.execution.DefaultExecutableInvoker");
    } catch (ClassNotFoundException e) {
      return Optional.empty();
    }
    // Get the private DefaultExecutableInvoker#extensionRegistry field, using the type rather than
    // the name for slightly better forwards compatibility.
    return Arrays.stream(DefaultExecutableInvoker.class.getDeclaredFields())
        .filter(field -> field.getType() == ExtensionRegistry.class)
        .findFirst()
        .flatMap(extensionRegistryField -> {
          DefaultExecutableInvoker invoker =
              (DefaultExecutableInvoker) extensionContext.getExecutableInvoker();
          long extensionRegistryFieldOffset =
              UnsafeProvider.getUnsafe().objectFieldOffset(extensionRegistryField);
          return Optional.ofNullable((ExtensionRegistry) UnsafeProvider.getUnsafe().getObject(
              invoker, extensionRegistryFieldOffset));
        });
  }

  @Override
  public void beforeFirstExecution() {}

  @Override
  public void beforeEachExecution() throws Throwable {
    if (timesCalledBetweenExecutions++ == 0) {
      // BeforeEach callbacks are run by JUnit right before the fuzz test starts executing and thus
      // shouldn't be run again before the first fuzz test execution.
      // AfterEach callbacks should be run between two executions and thus also not before the first
      // fuzz test execution.
      return;
    }
    for (ThrowingRunnable runnable : beforeEachExecutionRunnables) {
      runnable.run();
    }
  }

  @Override
  public void afterLastExecution() {}
}
