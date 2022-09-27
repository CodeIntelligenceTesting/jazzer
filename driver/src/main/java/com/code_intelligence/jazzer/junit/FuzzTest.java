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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/**
 * A {@link ParameterizedTest} with input data generated dynamically by the Java fuzzer <a
 * href="https://github.com/CodeIntelligenceTesting/jazzer">Jazzer</a>.
 *
 * When executed as a JUnit Jupiter test, the fuzz test is executed on all files in the seed corpus
 * (see documentation for the {@code seedCorpus} parameter.
 *
 * <p>Methods annotated with {@link FuzzTest} must take a single parameter of type {@code byte[]} or
 * {@link com.code_intelligence.jazzer.api.FuzzedDataProvider}. The latter provides convenience
 * methods to generate common Java types from the raw fuzzer input.
 *
 * <p>Only a single method per class can be annotated with {@link FuzzTest}.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(RegressionTestArgumentProvider.class)
@ExtendWith(RegressionTestExtensions.class)
// {0} is expanded to the basename of the seed by the ArgumentProvider.
@ParameterizedTest(name = "{0}")
@Tag("jazzer")
// JazzerInternal keeps global state about the last finding. Compared to the cost of starting up the
// agent, running individual regression test cases should be very fast, so we wouldn't gain much
// from parallelization.
@ResourceLock(value = "jazzer", mode = ResourceAccessMode.READ_WRITE)
public @interface FuzzTest {
  /**
   * A duration string such as "1h 2m 30s" indicating for how long the fuzz test should be executed
   * when fuzzing.
   *
   * <p>Defaults to 1 minute.
   */
  String maxDuration() default "1m";
}
