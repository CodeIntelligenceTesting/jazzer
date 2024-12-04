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

import static com.code_intelligence.jazzer.junit.FuzzerDictionary.createDictionaryFile;

import com.code_intelligence.jazzer.utils.Log;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;
import org.junit.platform.commons.support.AnnotationSupport;

class FuzzTestExtensions
    implements ExecutionCondition, InvocationInterceptor, TestExecutionExceptionHandler {
  private static final String JAZZER_INTERNAL =
      "com.code_intelligence.jazzer.runtime.JazzerInternal";
  private static final AtomicReference<Method> fuzzTestMethod = new AtomicReference<>();
  private static Field lastFindingField;
  private static Field hooksEnabledField;

  @Override
  public void interceptTestTemplateMethod(
      Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext,
      ExtensionContext extensionContext)
      throws Throwable {
    FuzzTest fuzzTest =
        AnnotationSupport.findAnnotation(invocationContext.getExecutable(), FuzzTest.class).get();
    Optional<Path> dictionaryPath = createDictionaryFile(extensionContext.getRequiredTestMethod());

    // We need to call this method here in addition to the call in AgentConfiguringArgumentsProvider
    // as that provider isn't invoked before fuzz test executions for the arguments provided by
    // user-provided ArgumentsProviders ("Java seeds").
    FuzzTestExecutor.configureAndInstallAgent(
        extensionContext, fuzzTest.maxDuration(), fuzzTest.maxExecutions(), dictionaryPath);
    // Skip the invocation of the test method with the special arguments provided by
    // FuzzTestArgumentsProvider and start fuzzing instead.
    if (Utils.isMarkedInvocation(invocationContext)) {
      startFuzzing(invocation, invocationContext, extensionContext, fuzzTest.lifecycle());
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
   *
   * <ol>
   *   <li>If a hook used Jazzer#reportFindingFromHook to explicitly report a finding, the last such
   *       finding, as stored in JazzerInternal#lastFinding, is reported.
   *   <li>If the fuzz target method threw a Throwable, that is reported.
   *   <li>3. Otherwise, nothing is reported.
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
    //
    // https://github.com/spring-projects/spring-boot/blob/main/spring-boot-project/spring-boot-tools/spring-boot-test-support/src/main/java/org/springframework/boot/testsupport/classpath/ModifiedClassPathExtension.java
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
      throw new FuzzTestFindingException(stored);
    } else if (thrown != null) {
      throw new FuzzTestFindingException(thrown);
    }
  }

  private static void startFuzzing(
      Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext,
      ExtensionContext extensionContext,
      Lifecycle lifecycle)
      throws Throwable {
    invocation.skip();
    Optional<Throwable> throwable =
        FuzzTestExecutor.fromContext(extensionContext)
            .execute(invocationContext, extensionContext, lifecycle);
    if (throwable.isPresent()) {
      throw throwable.get();
    }
  }

  private void recordSeedForFuzzing(List<Object> arguments, ExtensionContext extensionContext)
      throws IOException {
    SeedSerializer seedSerializer = getOrCreateSeedSerializer(extensionContext);
    byte[] seed;
    try {
      seed = seedSerializer.write(arguments.toArray());
    } catch (Exception ignored) {
      String argumentTypes =
          arguments.stream()
              .filter(Objects::nonNull)
              .map(obj -> obj.getClass().getName())
              .collect(Collectors.joining(","));
      String argumentValues =
          arguments.stream()
              .filter(Objects::nonNull)
              .map(Object::toString)
              .collect(Collectors.joining(", "));
      Log.warn(
          String.format(
              "JUnit arguments of type(s) %s with value(s) %s can not be serialized as fuzzing"
                  + " inputs. Skipped.",
              argumentTypes, argumentValues));
      return;
    }
    try {
      FuzzTestExecutor.fromContext(extensionContext).addSeed(seed);
    } catch (UnsupportedOperationException ignored) {
    }
  }

  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
    if (!Utils.isFuzzing(extensionContext)) {
      return ConditionEvaluationResult.enabled(
          "Regression tests are run instead of fuzzing since JAZZER_FUZZ has not been set to a"
              + " non-empty value");
    }
    // Only fuzz the first @FuzzTest that makes it here.
    if (FuzzTestExtensions.fuzzTestMethod.compareAndSet(
            null, extensionContext.getRequiredTestMethod())
        || extensionContext
            .getRequiredTestMethod()
            .equals(FuzzTestExtensions.fuzzTestMethod.get())) {
      return ConditionEvaluationResult.enabled(
          "Fuzzing " + extensionContext.getRequiredTestMethod());
    }
    return ConditionEvaluationResult.disabled(
        "Only one fuzz test can be run at a time, but multiple tests have been annotated with"
            + " @FuzzTest");
  }

  private static SeedSerializer getOrCreateSeedSerializer(ExtensionContext extensionContext) {
    Method method = extensionContext.getRequiredTestMethod();
    return extensionContext
        .getStore(Namespace.create(FuzzTestExtensions.class, method))
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

  @Override
  public void handleTestExecutionException(ExtensionContext extensionContext, Throwable throwable)
      throws Throwable {
    if (throwable instanceof ParameterResolutionException) {
      // JUnit does not provide direct information about which parameters of a given method can be
      // resolved dynamically by ParameterResolvers. The ExecutableInvoker interface only allows to
      // call methods that only take dynamically resolved parameters. We thus can't support fuzz
      // test methods that rely on ParameterResolver and tell the user about this limitation when
      // the invocation fails.
      throw new FuzzTestConfigurationError(
          "@FuzzTest does not support parameters resolved via ParameterResolvers. Instead of "
              + "injecting objects via test method parameters, inject them via test instance "
              + "properties. Note that test instances are reused across all invocations during "
              + "fuzzing.",
          throwable);
    } else {
      throw throwable;
    }
  }
}
