/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

import static com.code_intelligence.jazzer.junit.Utils.getClassPathBasedInstrumentationFilter;
import static com.code_intelligence.jazzer.junit.Utils.getLegacyInstrumentationFilter;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;

import com.code_intelligence.jazzer.driver.Opt;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.extension.ExtensionContext;

class AgentConfigurator {
  private static final AtomicBoolean hasBeenConfigured = new AtomicBoolean();

  static void forRegressionTest(ExtensionContext extensionContext) {
    if (!hasBeenConfigured.compareAndSet(false, true)) {
      return;
    }

    applyCommonConfiguration(extensionContext);

    // Add logic to the hook instrumentation that allows us to enable and disable hooks at runtime.
    Opt.conditionalHooks.setIfDefault(true);
    // Apply all hooks, but no coverage or compare instrumentation.
    Opt.instrumentationExcludes.setIfDefault(singletonList("**"));
    Opt.customHookIncludes.setIfDefault(Opt.instrument.get());
  }

  static void forFuzzing(ExtensionContext extensionContext) {
    if (!hasBeenConfigured.compareAndSet(false, true)) {
      throw new IllegalStateException("Only a single fuzz test should be executed per fuzzing run");
    }

    applyCommonConfiguration(extensionContext);

    Opt.instrument.setIfDefault(
        getClassPathBasedInstrumentationFilter(System.getProperty("java.class.path"))
            .orElseGet(
                () -> getLegacyInstrumentationFilter(extensionContext.getRequiredTestClass())));
    Opt.customHookIncludes.setIfDefault(Opt.instrument.get());
    Opt.instrumentationIncludes.setIfDefault(Opt.instrument.get());
  }

  private static void applyCommonConfiguration(ExtensionContext extensionContext) {
    Opt.registerConfigurationParameters(extensionContext::getConfigurationParameter);
    // Do not hook common IDE and JUnit classes and their dependencies.
    Opt.customHookExcludes.setIfDefault(
        asList(
            "com.google.testing.junit.**",
            "com.intellij.**",
            "org.jetbrains.**",
            "io.github.classgraph.**",
            "junit.framework.**",
            "net.bytebuddy.**",
            "org.apiguardian.**",
            "org.assertj.core.**",
            "org.hamcrest.**",
            "org.junit.**",
            "org.opentest4j.**",
            "org.mockito.**",
            "org.apache.maven.**",
            "org.gradle.**"));
  }
}
