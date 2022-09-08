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

import com.code_intelligence.jazzer.Constants;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.commons.support.HierarchyTraversalMode;
import org.junit.platform.commons.support.ReflectionSupport;
import org.junit.platform.engine.EngineDiscoveryRequest;
import org.junit.platform.engine.EngineExecutionListener;
import org.junit.platform.engine.ExecutionRequest;
import org.junit.platform.engine.TestDescriptor;
import org.junit.platform.engine.TestEngine;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.engine.discovery.ClassSelector;
import org.junit.platform.engine.discovery.ClasspathRootSelector;
import org.junit.platform.engine.discovery.MethodSelector;
import org.junit.platform.engine.discovery.PackageSelector;
import org.junit.platform.engine.support.descriptor.AbstractTestDescriptor;
import org.junit.platform.engine.support.descriptor.EngineDescriptor;

public class JazzerTestEngine implements TestEngine {
  static class JazzerSetupError extends Error {
    public JazzerSetupError(Throwable e) {
      super("Jazzer fuzz test failed to execute", e);
    }
    public JazzerSetupError(String message) {
      super(message);
    }
  }

  static class JazzerFuzzTestDescriptor extends AbstractTestDescriptor {
    private final Method method;

    public JazzerFuzzTestDescriptor(UniqueId uniqueId, Method method) {
      super(uniqueId.append("class", method.getDeclaringClass().getName())
                .append("method",
                    new DisplayNameGenerator.Standard().generateDisplayNameForMethod(
                        method.getDeclaringClass(), method)),
          makeDisplayName(method));
      this.method = method;
    }

    @Override
    public Type getType() {
      return Type.TEST;
    }

    public Method getMethod() {
      return method;
    }
  }

  private static final String JAZZER_FUZZ = System.getenv("JAZZER_FUZZ");

  @Override
  public String getId() {
    return "com.code_intelligence.jazzer";
  }

  @Override
  public TestDescriptor discover(EngineDiscoveryRequest request, UniqueId uniqueId) {
    TestDescriptor engineDescriptor = new EngineDescriptor(uniqueId, "Jazzer");

    if (JAZZER_FUZZ == null || JAZZER_FUZZ.isEmpty()) {
      // Fuzz tests are executed as regression tests by the Jupiter engine.
      return engineDescriptor;
    }

    request.getSelectorsByType(ClasspathRootSelector.class)
        .stream()
        .flatMap(classpathRootSelector
            -> ReflectionSupport
                   .findAllClassesInClasspathRoot(
                       classpathRootSelector.getClasspathRoot(), (name) -> true, (name) -> true)
                   .stream())
        .flatMap(clazz
            -> AnnotationSupport
                   .findAnnotatedMethods(clazz, FuzzTest.class, HierarchyTraversalMode.TOP_DOWN)
                   .stream())
        .forEach(method -> JazzerTestEngine.addDescriptor(engineDescriptor, method));

    request.getSelectorsByType(PackageSelector.class)
        .stream()
        .flatMap(packageSelector
            -> ReflectionSupport
                   .findAllClassesInPackage(
                       packageSelector.getPackageName(), (name) -> true, (name) -> true)
                   .stream())
        .flatMap(clazz
            -> AnnotationSupport
                   .findAnnotatedMethods(clazz, FuzzTest.class, HierarchyTraversalMode.TOP_DOWN)
                   .stream())
        .forEach(method -> JazzerTestEngine.addDescriptor(engineDescriptor, method));

    request.getSelectorsByType(ClassSelector.class)
        .stream()
        .map(ClassSelector::getJavaClass)
        .flatMap(clazz
            -> AnnotationSupport
                   .findAnnotatedMethods(clazz, FuzzTest.class, HierarchyTraversalMode.TOP_DOWN)
                   .stream())
        .forEach(method -> JazzerTestEngine.addDescriptor(engineDescriptor, method));

    request.getSelectorsByType(MethodSelector.class)
        .stream()
        .map(MethodSelector::getJavaMethod)
        .filter(method -> AnnotationSupport.isAnnotated(method, FuzzTest.class))
        .forEach(method -> addDescriptor(engineDescriptor, method));

    return engineDescriptor;
  }

  private static void addDescriptor(TestDescriptor engineDescriptor, Method method) {
    engineDescriptor.addChild(new JazzerFuzzTestDescriptor(engineDescriptor.getUniqueId(), method));
  }

  @Override
  public void execute(ExecutionRequest executionRequest) {
    EngineExecutionListener listener = executionRequest.getEngineExecutionListener();

    AtomicBoolean hasFuzzTestBeenStarted = new AtomicBoolean();
    // With JUnit, the current working directory is the project directory (or module directory in
    // case of a multi-module project). We only override this path in tests.
    Path baseDir = Paths.get(
        executionRequest.getConfigurationParameters().get("jazzer.internal.basedir").orElse(""));

    executionRequest.getRootTestDescriptor().accept(testDescriptor -> {
      if (!testDescriptor.isTest()) {
        // Our only non-test descriptor is the engine descriptor. Start it here and report it
        // finished after the visitor has returned.
        listener.executionStarted(testDescriptor);
        return;
      }

      JazzerFuzzTestDescriptor fuzzTestDescriptor = (JazzerFuzzTestDescriptor) testDescriptor;

      if (!hasFuzzTestBeenStarted.compareAndSet(false, true)) {
        // Another fuzz test has been started - we can't yet run fuzz tests in parallel due to
        // global state in libFuzzer and thus skip all other tests.
        listener.executionSkipped(testDescriptor,
            "This fuzz test has been skipped as another one is already executing - the Jazzer "
                + "JUnit test engine can only execute a single fuzz test per test run.");
        return;
      }

      listener.executionStarted(testDescriptor);
      try {
        TestExecutionResult result =
            new JazzerFuzzTestExecutor(executionRequest, fuzzTestDescriptor, baseDir).execute();
        listener.executionFinished(testDescriptor, result);
      } catch (Throwable e) {
        listener.executionFinished(
            testDescriptor, TestExecutionResult.failed(new JazzerSetupError(e)));
      }
    });

    // The individual tests are reported as finished in the accept call above. Since they are
    // executed synchronously, at this point we know they are all done and can thus report their
    // container, the engine test descriptor, as finished.
    // Note: Containers should report a successful execution even if individual tests fail.
    listener.executionFinished(
        executionRequest.getRootTestDescriptor(), TestExecutionResult.successful());
  }

  @Override
  public Optional<String> getGroupId() {
    return Optional.of("com.code-intelligence");
  }

  @Override
  public Optional<String> getArtifactId() {
    return Optional.of("jazzer-junit");
  }

  @Override
  public Optional<String> getVersion() {
    return Optional.of(Constants.JAZZER_VERSION);
  }

  private static String makeDisplayName(Method method) {
    return new DisplayNameGenerator.Standard().generateDisplayNameForMethod(
               method.getDeclaringClass(), method)
        + " (Fuzzing)";
  }
}
