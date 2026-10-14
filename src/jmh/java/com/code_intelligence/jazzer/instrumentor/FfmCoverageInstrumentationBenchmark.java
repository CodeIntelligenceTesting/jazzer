/*
 * Copyright 2026 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.instrumentor;

import java.lang.invoke.MethodHandle;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * Complements {@link CoverageInstrumentationBenchmark} with coverage maps backed by the Foreign
 * Function & Memory API. Since that API requires JDK 22+, this class is only compiled when building
 * with {@code --java_runtime_version=remotejdk_25}, see BUILD.bazel.
 */
@State(Scope.Benchmark)
public class FfmCoverageInstrumentationBenchmark {
  // This is part of the benchmark's state and not a constant to prevent constant folding.
  String TARGET_ARG = CoverageInstrumentationBenchmark.SAMPLE_INPUT;

  MethodHandle staticMethod_Ffm_NeverZero_sanitize;
  MethodHandle staticMethod_FfmMethodHandle_NeverZero_sanitize;

  @Setup
  public void instrumentWithStrategies()
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException {
    staticMethod_Ffm_NeverZero_sanitize =
        CoverageInstrumentationBenchmark.instrumentWithStrategy(
            new StaticMethodStrategy(), FfmCoverageMap.class);
    staticMethod_FfmMethodHandle_NeverZero_sanitize =
        CoverageInstrumentationBenchmark.instrumentWithStrategy(
            new StaticMethodStrategy(), FfmMethodHandleCoverageMap.class);
  }

  @Benchmark
  public String staticMethod_Ffm_NeverZero() throws Throwable {
    return (String) staticMethod_Ffm_NeverZero_sanitize.invokeExact(TARGET_ARG);
  }

  @Benchmark
  public String staticMethod_FfmMethodHandle_NeverZero() throws Throwable {
    return (String) staticMethod_FfmMethodHandle_NeverZero_sanitize.invokeExact(TARGET_ARG);
  }
}
