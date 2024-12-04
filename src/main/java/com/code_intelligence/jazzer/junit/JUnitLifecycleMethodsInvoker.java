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

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toCollection;

import com.code_intelligence.jazzer.driver.LifecycleMethodsInvoker;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.lang.reflect.Constructor;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;
import org.junit.jupiter.api.extension.TestInstances;
import org.junit.jupiter.engine.execution.AfterEachMethodAdapter;
import org.junit.jupiter.engine.execution.BeforeEachMethodAdapter;
import org.junit.jupiter.engine.execution.DefaultExecutableInvoker;
import org.junit.jupiter.engine.extension.ExtensionRegistry;

/**
 * Adapts JUnit BeforeEach and AfterEach callbacks to {@link
 * com.code_intelligence.jazzer.driver.FuzzTargetRunner} lifecycle hooks.
 */
final class JUnitLifecycleMethodsInvoker implements LifecycleMethodsInvoker {
  private final ThrowingRunnable testClassInstanceUpdater;
  private final Supplier<Object> testClassInstanceSupplier;
  private final ThrowingRunnable[] beforeEachRunnables;
  private final ThrowingRunnable[] afterEachRunnables;

  private JUnitLifecycleMethodsInvoker(
      ThrowingRunnable testClassInstanceUpdater,
      Supplier<Object> testClassInstanceSupplier,
      ThrowingRunnable[] beforeEachRunnables,
      ThrowingRunnable[] afterEachRunnables) {
    this.testClassInstanceUpdater = testClassInstanceUpdater;
    this.testClassInstanceSupplier = testClassInstanceSupplier;
    this.beforeEachRunnables = beforeEachRunnables;
    this.afterEachRunnables = afterEachRunnables;
  }

  static LifecycleMethodsInvoker of(
      ExtensionContext originalExtensionContext, Lifecycle lifecycleMode) {
    if (lifecycleMode == Lifecycle.PER_TEST) {
      return LifecycleMethodsInvoker.noop(originalExtensionContext.getRequiredTestInstance());
    }
    if (originalExtensionContext.getTestInstances().isPresent()
        && originalExtensionContext.getTestInstances().get().getAllInstances().size() > 1) {
      throw new IllegalArgumentException(
          "Jazzer does not support nested test classes with LifecycleMode.PER_EXECUTION. Either"
              + " move your fuzz test to a top-level class or set lifecycle ="
              + " LifecycleMode.PER_TEST on @FuzzTest.");
    }
    // ExtensionRegistry is private JUnit API that is the source of truth for all lifecycle
    // callbacks, both annotation- and extension-based.
    Optional<ExtensionRegistry> maybeExtensionRegistry =
        getExtensionRegistryViaHack(originalExtensionContext);
    if (!maybeExtensionRegistry.isPresent()) {
      throw new IllegalArgumentException(
          "Jazzer does not support BeforeEach and AfterEach callbacks with this version of JUnit."
              + " Either update to at least JUnit 5.9.0 or set lifecycle = LifecycleMode.PER_TEST"
              + " on @FuzzTest.");
    }
    ExtensionRegistry extensionRegistry = maybeExtensionRegistry.get();

    // Use a one-element array as a mutable container for use in lambdas. We do not need
    // synchronization and thus don't use AtomicReference.
    Object[] mutableTestClassInstance = new Object[1];
    mutableTestClassInstance[0] = originalExtensionContext.getRequiredTestInstance();
    TestInstances testInstances =
        makeTestInstances(
            originalExtensionContext.getRequiredTestClass(), () -> mutableTestClassInstance[0]);
    // An ExtensionContext for lifecycle callbacks that do not contain a test instance. This is
    // currently only TestInstancePostProcessor.
    ExtensionContext emptyExtensionContext =
        (ExtensionContext)
            Proxy.newProxyInstance(
                JUnitLifecycleMethodsInvoker.class.getClassLoader(),
                new Class[] {ExtensionContext.class},
                (obj, method, args) -> {
                  switch (method.getName()) {
                    case "getTestInstance":
                    case "getTestInstances":
                      return Optional.empty();
                    case "getRequiredTestInstance":
                    case "getRequiredTestInstances":
                      return Optional.empty().get();
                    default:
                      return method.invoke(originalExtensionContext, args);
                  }
                });
    // An ExtensionContext that returns the current test instance stored in
    // mutableTestClassInstance.
    ExtensionContext updatingExtensionContext =
        (ExtensionContext)
            Proxy.newProxyInstance(
                JUnitLifecycleMethodsInvoker.class.getClassLoader(),
                new Class[] {ExtensionContext.class},
                (obj, method, args) -> {
                  switch (method.getName()) {
                    case "getTestInstance":
                      return Optional.of(mutableTestClassInstance[0]);
                    case "getRequiredTestInstance":
                      return mutableTestClassInstance[0];
                    case "getTestInstances":
                      return Optional.of(testInstances);
                    case "getRequiredTestInstances":
                      return testInstances;
                    default:
                      return method.invoke(originalExtensionContext, args);
                  }
                });

    // BeforeEachCallback implementations take precedence over @BeforeEach methods. The annotations
    // are turned into extensions using an internal adapter class, BeforeEachMethodAdapter.
    // https://junit.org/junit5/docs/current/user-guide/#extensions-execution-order-wrapping-behavior
    ThrowingRunnable[] beforeEachMethods =
        Stream.<ThrowingRunnable>concat(
                extensionRegistry.stream(BeforeEachCallback.class)
                    .map(callback -> () -> callback.beforeEach(updatingExtensionContext)),
                extensionRegistry.stream(BeforeEachMethodAdapter.class)
                    .map(
                        callback ->
                            () ->
                                callback.invokeBeforeEachMethod(
                                    updatingExtensionContext, extensionRegistry)))
            .toArray(ThrowingRunnable[]::new);

    ArrayList<ThrowingRunnable> afterEachMethods =
        Stream.<ThrowingRunnable>concat(
                extensionRegistry.stream(AfterEachCallback.class)
                    .map(callback -> () -> callback.afterEach(updatingExtensionContext)),
                extensionRegistry.stream(AfterEachMethodAdapter.class)
                    .map(
                        callback ->
                            () ->
                                callback.invokeAfterEachMethod(
                                    updatingExtensionContext, extensionRegistry)))
            .collect(toCollection(ArrayList::new));
    // JUnit calls AfterEach methods in reverse order of registration so that the methods registered
    // first run last.
    Collections.reverse(afterEachMethods);

    Constructor<?> constructor = getTestClassNoArgsConstructor(updatingExtensionContext);
    ThrowingConsumer[] instancePostProcessors =
        extensionRegistry.stream(TestInstancePostProcessor.class)
            .map(
                processor ->
                    (ThrowingConsumer)
                        (instance ->
                            processor.postProcessTestInstance(instance, emptyExtensionContext)))
            .toArray(ThrowingConsumer[]::new);
    ThrowingRunnable updateTestClassInstance =
        () -> {
          Object instance = constructor.newInstance();
          for (ThrowingConsumer instancePostProcessor : instancePostProcessors) {
            instancePostProcessor.accept(instance);
          }
          mutableTestClassInstance[0] = instance;
        };

    return new JUnitLifecycleMethodsInvoker(
        updateTestClassInstance,
        () -> mutableTestClassInstance[0],
        beforeEachMethods,
        afterEachMethods.toArray(new ThrowingRunnable[0]));
  }

  private static TestInstances makeTestInstances(
      Class<?> clazz, Supplier<Object> singleTestInstance) {
    return new TestInstances() {
      @Override
      public Object getInnermostInstance() {
        return singleTestInstance.get();
      }

      @Override
      public List<Object> getEnclosingInstances() {
        return emptyList();
      }

      @Override
      public List<Object> getAllInstances() {
        return singletonList(singleTestInstance.get());
      }

      @Override
      public <T> Optional<T> findInstance(Class<T> aClass) {
        if (clazz == aClass) {
          return (Optional<T>) Optional.of(singleTestInstance.get());
        } else {
          return Optional.empty();
        }
      }
    };
  }

  private static Constructor<?> getTestClassNoArgsConstructor(ExtensionContext extensionContext) {
    Class<?> testClass = extensionContext.getRequiredTestClass();
    if (testClass.getEnclosingClass() != null) {
      throw new IllegalArgumentException(
          String.format(
              "The test class %s is an inner class, which is not supported with"
                  + " LifecycleMode.PER_EXECUTION. Either make it a top-level class or set"
                  + " lifecycle = LifecycleMode.PER_TEST on @FuzzTest.",
              testClass.getName()));
    }
    try {
      Constructor<?> constructor = testClass.getDeclaredConstructor();
      constructor.setAccessible(true);
      return constructor;
    } catch (NoSuchMethodException e) {
      throw new IllegalArgumentException(
          String.format(
              "The test class %s has no default constructor, which is not supported with"
                  + " LifecycleMode.PER_EXECUTION. Either add such a constructor or set lifecycle"
                  + " = LifecycleMode.PER_TEST on @FuzzTest.",
              testClass.getName()));
    }
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
        .flatMap(
            extensionRegistryField -> {
              DefaultExecutableInvoker invoker =
                  (DefaultExecutableInvoker) extensionContext.getExecutableInvoker();
              long extensionRegistryFieldOffset =
                  UnsafeProvider.getUnsafe().objectFieldOffset(extensionRegistryField);
              return Optional.ofNullable(
                  (ExtensionRegistry)
                      UnsafeProvider.getUnsafe().getObject(invoker, extensionRegistryFieldOffset));
            });
  }

  @Override
  public void beforeFirstExecution() {
    /*
     @BeforeAll methods are called by JUnit.
     Note: JUnit runs a full lifecycle on the instance it created, but we don't use it: Before
     our first execution, it runs the before each methods and then, after our last one, the after
     each methods. This may result in compatibility issues since we run the actual fuzzing
     executions between the before and after each callbacks for this instance. If the callbacks rely
     on globally unique resources (e.g. file locks), this will fail, but it is consistent with
     behavior a regular parameterized unit test could show when executed concurrently.

     Alternatives considered:
     * Running the after each methods after the before each methods and keeping the instance
       alive so that we can run the before each methods again before JUnit runs the after
       each methods. This resolves the bracketing problem, but may also lead to issues since
       JUnit would never invoke before each callbacks again on the same instance (e.g. the
       instance may be in an unexpected state that doesn't result from construction +
       post processing callbacks).
     * Skipping the invocation of before/after each callbacks in JUnit. This is possible for
       @BeforeEach/@AfterEach via an interceptor, but doesn't seem to be possible for
       BeforeEachCallback/AfterEachCallback.
    */
  }

  @Override
  public void beforeEachExecution() throws Throwable {
    testClassInstanceUpdater.run();
    for (ThrowingRunnable runnable : beforeEachRunnables) {
      runnable.run();
    }
  }

  @Override
  public void afterEachExecution() throws Throwable {
    for (ThrowingRunnable runnable : afterEachRunnables) {
      runnable.run();
    }
  }

  @Override
  public void afterLastExecution() {
    // @AfterAll methods are called by JUnit.
  }

  @Override
  public Object getTestClassInstance() {
    return testClassInstanceSupplier.get();
  }

  @FunctionalInterface
  interface ThrowingConsumer {

    void accept(Object o) throws Exception;
  }
}
