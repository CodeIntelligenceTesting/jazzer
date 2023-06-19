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

import static com.code_intelligence.jazzer.junit.Utils.getClassPathBasedInstrumentationFilter;
import static com.code_intelligence.jazzer.junit.Utils.getLegacyInstrumentationFilter;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;

import com.code_intelligence.jazzer.driver.Opt;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.extension.ExtensionContext;

class AgentConfigurator {
  private static final AtomicBoolean hasBeenConfigured = new AtomicBoolean();

  static void forRegressionTest(ExtensionContext extensionContext) {
    if (!hasBeenConfigured.compareAndSet(false, true)) {
      return;
    }

    applyCommonConfiguration();

    // Add logic to the hook instrumentation that allows us to enable and disable hooks at runtime.
    Opt.conditionalHooks.setIfDefault(true);
    // Apply all hooks, but no coverage or compare instrumentation.
    Opt.instrumentationIncludes.setIfDefault(singletonList("**"));
    Opt.instrumentationExcludes.setIfDefault(singletonList("**"));
    extensionContext.getConfigurationParameter("jazzer.instrument")
        .ifPresent(s -> Opt.customHookIncludes.setIfDefault(asList(s.split(","))));
  }

  static void forFuzzing(ExtensionContext executionRequest) {
    if (!hasBeenConfigured.compareAndSet(false, true)) {
      throw new IllegalStateException("Only a single fuzz test should be executed per fuzzing run");
    }

    applyCommonConfiguration();

    String instrumentationFilter =
        executionRequest.getConfigurationParameter("jazzer.instrument")
            .orElseGet(
                ()
                    -> getClassPathBasedInstrumentationFilter(System.getProperty("java.class.path"))
                           .orElseGet(()
                                          -> getLegacyInstrumentationFilter(
                                              executionRequest.getRequiredTestClass())));
    List<String> includes = asList(instrumentationFilter.split(","));
    Opt.customHookIncludes.setIfDefault(includes);
    Opt.instrumentationIncludes.setIfDefault(includes);
  }

  private static void applyCommonConfiguration() {
    // Do not hook common IDE and JUnit classes and their dependencies.
    Opt.customHookExcludes.setIfDefault(asList("com.google.testing.junit.**", "com.intellij.**",
        "org.jetbrains.**", "io.github.classgraph.**", "junit.framework.**", "net.bytebuddy.**",
        "org.apiguardian.**", "org.assertj.core.**", "org.hamcrest.**", "org.junit.**",
        "org.opentest4j.**", "org.mockito.**", "org.apache.maven.**", "org.gradle.**"));
  }
}
