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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.platform.commons.support.AnnotationSupport;

class FuzzTestExtensions implements ExecutionCondition, InvocationInterceptor {
  private static final String JAZZER_INTERNAL =
      "com.code_intelligence.jazzer.runtime.JazzerInternal";
  private static final AtomicReference<Method> fuzzTestMethod = new AtomicReference<>();
  private static Field lastFindingField;
  private static Field hooksEnabledField;

  @Override
  public void interceptTestTemplateMethod(Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext, ExtensionContext extensionContext)
      throws Throwable {
    FuzzTest fuzzTest =
        AnnotationSupport.findAnnotation(invocationContext.getExecutable(), FuzzTest.class).get();
    FuzzTestExecutor.configureAndInstallAgent(extensionContext, fuzzTest.maxDuration());
    // Skip the invocation of the test method with the special arguments provided by
    // FuzzTestArgumentsProvider and start fuzzing instead.
    if (Utils.isMarkedInvocation(invocationContext)) {
      startFuzzing(invocation, invocationContext, extensionContext);
    } else {
      // Blocked by https://github.com/junit-team/junit5/issues/3282:
      // TODO: The seeds from the input directory are duplicated here as there is no way to
      //  recognize them.
      // TODO: Error out if there is a non-Jazzer ArgumentsProvider and the SeedSerializer does not
      //  support write.
      if (Utils.isFuzzing(extensionContext)) {
        // JUnit verifies that the arguments for this invocation are valid.
        recordSeedForFuzzing(invocationContext.getArguments(), extensionContext);
      }
      runWithHooks(invocation);
    }
  }

  /**
   * Mimics the logic of Jazzer's FuzzTargetRunner, which reports findings in the following way:
   * <ol>
   *   <li>If a hook used Jazzer#reportFindingFromHook to explicitly report a finding, the last such
   * finding, as stored in JazzerInternal#lastFinding, is reported. <li>If the fuzz target method
   * threw a Throwable, that is reported. <li>3. Otherwise, nothing is reported.
   * </ol>
   */
  private static void runWithHooks(Invocation<Void> invocation) throws Throwable {
    Throwable thrown = null;
    getLastFindingField().set(null, null);
    // When running in regression test mode, the agent emits additional bytecode logic in front of
    // method hook invocations that enables them only while a global variable managed by
    // withHooksEnabled is true.
    //
    // Alternatives considered:
    // * Using a dedicated class loader for @FuzzTests: First-class support for this isn't
    //   available in JUnit 5 (https://github.com/junit-team/junit5/issues/201), but
    //   third-party extensions have done it:
    //   https://github.com/spring-projects/spring-boot/blob/main/spring-boot-project/spring-boot-tools/spring-boot-test-support/src/main/java/org/springframework/boot/testsupport/classpath/ModifiedClassPathExtension.java
    //   However, as this involves launching a new test run as part of running a test, this
    //   introduces a number of inconsistencies if applied on the test method rather than test
    //   class level. For example, @BeforeAll methods will have to be run twice in different class
    //   loaders, which may not be safe if they are using global resources not separated by class
    //   loaders (e.g. files).
    try (AutoCloseable ignored = withHooksEnabled()) {
      invocation.proceed();
    } catch (Throwable t) {
      thrown = t;
    }
    Throwable stored = (Throwable) getLastFindingField().get(null);
    if (stored != null) {
      throw stored;
    } else if (thrown != null) {
      throw thrown;
    }
  }

  private static void startFuzzing(Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext, ExtensionContext extensionContext)
      throws Throwable {
    invocation.skip();
    Optional<Throwable> throwable =
        FuzzTestExecutor.fromContext(extensionContext)
            .execute(invocationContext, getOrCreateSeedSerializer(extensionContext));
    if (throwable.isPresent()) {
      throw throwable.get();
    }
  }

  private void recordSeedForFuzzing(List<Object> arguments, ExtensionContext extensionContext)
      throws IOException {
    SeedSerializer seedSerializer = getOrCreateSeedSerializer(extensionContext);
    try {
      FuzzTestExecutor.fromContext(extensionContext)
          .addSeed(seedSerializer.write(arguments.toArray()));
    } catch (UnsupportedOperationException ignored) {
    }
  }

  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
    if (!Utils.isFuzzing(extensionContext)) {
      return ConditionEvaluationResult.enabled(
          "Regression tests are run instead of fuzzing since JAZZER_FUZZ has not been set to a non-empty value");
    }
    // Only fuzz the first @FuzzTest that makes it here.
    if (FuzzTestExtensions.fuzzTestMethod.compareAndSet(
            null, extensionContext.getRequiredTestMethod())
        || extensionContext.getRequiredTestMethod().equals(
            FuzzTestExtensions.fuzzTestMethod.get())) {
      return ConditionEvaluationResult.enabled(
          "Fuzzing " + extensionContext.getRequiredTestMethod());
    }
    return ConditionEvaluationResult.disabled(
        "Only one fuzz test can be run at a time, but multiple tests have been annotated with @FuzzTest");
  }

  private static SeedSerializer getOrCreateSeedSerializer(ExtensionContext extensionContext) {
    Method method = extensionContext.getRequiredTestMethod();
    return extensionContext.getStore(Namespace.create(FuzzTestExtensions.class, method))
        .getOrComputeIfAbsent(
            SeedSerializer.class, unused -> SeedSerializer.of(method), SeedSerializer.class);
  }

  private static Field getLastFindingField() throws ClassNotFoundException, NoSuchFieldException {
    if (lastFindingField == null) {
      Class<?> jazzerInternal = Class.forName(JAZZER_INTERNAL);
      lastFindingField = jazzerInternal.getField("lastFinding");
    }
    return lastFindingField;
  }

  private static Field getHooksEnabledField() throws ClassNotFoundException, NoSuchFieldException {
    if (hooksEnabledField == null) {
      Class<?> jazzerInternal = Class.forName(JAZZER_INTERNAL);
      hooksEnabledField = jazzerInternal.getField("hooksEnabled");
    }
    return hooksEnabledField;
  }

  private static AutoCloseable withHooksEnabled()
      throws NoSuchFieldException, ClassNotFoundException, IllegalAccessException {
    Field hooksEnabledField = getHooksEnabledField();
    hooksEnabledField.setBoolean(null, true);
    return () -> hooksEnabledField.setBoolean(null, false);
  }
}
