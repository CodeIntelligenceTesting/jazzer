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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/**
 * A parameterized test with parameters generated automatically by the Java fuzzer <a
 * href="https://github.com/CodeIntelligenceTesting/jazzer">Jazzer</a>.
 *
 * <h2>Test parameters</h2>
 *
 * <p>Methods annotated with {@link FuzzTest} can take either of the following types of parameters:
 *
 * <dl>
 *   <dt>{@code byte[]}
 *   <dd>Raw byte input mutated by the fuzzer. Use this signature when your fuzz test naturally
 *       handles raw bytes (e.g. when fuzzing a binary format parser). This is the most efficient,
 *       but also the least convenient way to write a fuzz test.
 *   <dt>{@link com.code_intelligence.jazzer.api.FuzzedDataProvider}
 *   <dd>Provides convenience methods that generate instances of commonly used Java types from the
 *       raw fuzzer input. This is generally the best way to write fuzz tests.
 *   <dt>any non-zero number of parameters of any type
 *   <dd>In this case, Jazzer will rely on reflection and class path scanning to instantiate
 *       concrete arguments. While convenient and a good way to get started, fuzz tests using this
 *       feature will generally be less efficient than fuzz tests using any of the other possible
 *       signatures. Due to the reliance on class path scanning, any change to the class path may
 *       also render previous findings unreproducible.
 * </dl>
 *
 * <p>The {@link FuzzTest} annotation can also be applied to another annotations as a
 * meta-annotation and then applies to all methods annotated with that annotation. This can be used
 * to create reusable custom annotations for fuzz tests combined with other JUnit annotations such
 * as {@link org.junit.jupiter.api.Timeout} or {@link org.junit.jupiter.api.Tag}.
 *
 * <h2>Test modes</h2>
 *
 * A fuzz test can be run in two modes: fuzzing and regression testing.
 *
 * <h3>Fuzzing</h3>
 *
 * <p>When the environment variable {@code JAZZER_FUZZ} is set to any non-empty value, fuzz tests
 * run in "fuzzing" mode. In this mode, the method annotated with {@link FuzzTest} are invoked
 * repeatedly with inputs that Jazzer generates and mutates based on feedback obtained from
 * instrumentation it applies to the test and every class loaded by it.
 *
 * <p>When an assertion in the test fails, an exception is thrown but not caught, or Jazzer's
 * instrumentation detects a security issue (e.g. SQL injection or insecure deserialization), the
 * fuzz test is reported as failed and the input is collected in the inputs directory for the test
 * class (see "Regression testing" for details).
 *
 * <p>When no issue has been found after the configured {@link FuzzTest#maxDuration()}, the test
 * passes.
 *
 * <p><b>In fuzzing mode, only a single fuzz test per test run will be executed.</b> All other fuzz
 * tests will be skipped.
 *
 * <h3>Regression testing</h3>
 *
 * <p>By default, a fuzz test is executed as a regular JUnit {@link ParameterizedTest} running on a
 * fixed set of inputs. It can be run together with regular unit tests and used to verify that past
 * findings remain fixed. In IDEs with JUnit 5 integration, it can also be used to conveniently
 * debug individual findings.
 *
 * <p>Fuzz tests are always executed on the empty input as well as all input files contained in the
 * resource directory called {@code <TestClassName>Inputs} in the current package. For example, all
 * fuzz tests contained in the class {@code com.example.MyFuzzTests} would run on all files under
 * {@code src/test/resources/com/example/MyFuzzTestsInputs}.
 */
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@AgentConfiguringArgumentsProviderArgumentsSource
@ArgumentsSource(SeedArgumentsProvider.class)
@FuzzingArgumentsProviderArgumentsSource
@ExtendWith(FuzzTestExtensions.class)
// {0} is expanded to the basename of the seed by the ArgumentProvider.
@ParameterizedTest(name = "{0}")
@Tag("jazzer")
// Fuzz tests can't run in parallel with other fuzz tests since the last finding is kept in a global
// variable.
// Fuzz tests also can't run in parallel with other non-fuzz tests since method hooks are enabled
// conditionally based on a global variable.
@ResourceLock(value = Resources.GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public @interface FuzzTest {
  /**
   * A duration string such as "1h 2m 30s" indicating for how long the fuzz test should be executed
   * during fuzzing.
   *
   * <p>To remove the default limit of 5 minutes, set this element to {@code ""}.
   *
   * <p>This option has no effect during regression testing.
   */
  String maxDuration() default "5m";

  /**
   * If set to a positive number, the fuzz test function will be executed at most this many times
   * during fuzzing. Otherwise (default), there is no bound on the number of executions.
   *
   * <p>Prefer this element over {@link #maxDuration()} if you want to ensure comparable levels of
   * fuzzing across machine's with different performance characteristics.
   *
   * <p>This option has no effect during regression testing.
   */
  long maxExecutions() default 0;

  /**
   * Controls the JUnit lifecycle of fuzz tests during fuzzing.
   *
   * <p>During regression testing, fuzz tests always go through the full JUnit lifecycle for every
   * execution regardless of the value of this option.
   */
  Lifecycle lifecycle() default Lifecycle.PER_TEST;
}

// Internal use only.
// These wrappers are needed only because the container annotation for @ArgumentsSource,
// @ArgumentsSources, can't be applied to annotations.
@Target({ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(AgentConfiguringArgumentsProvider.class)
@interface AgentConfiguringArgumentsProviderArgumentsSource {}

@Target({ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(FuzzingArgumentsProvider.class)
@interface FuzzingArgumentsProviderArgumentsSource {}
