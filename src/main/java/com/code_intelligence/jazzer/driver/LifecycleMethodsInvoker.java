/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.driver;

/**
 * Can provide callbacks to be invoked by {@link FuzzTargetRunner} at certain times during the
 * execution of a fuzz target.
 */
public interface LifecycleMethodsInvoker {
  /**
   * Returns an implementation of {@link LifecycleMethodsInvoker} with no lifecycle methods and a
   * fixed test class instance.
   */
  static LifecycleMethodsInvoker noop(Object fixedInstance) {
    return new LifecycleMethodsInvoker() {
      @Override
      public void beforeFirstExecution() {}

      @Override
      public void beforeEachExecution() {}

      @Override
      public void afterEachExecution() {}

      @Override
      public void afterLastExecution() {}

      @Override
      public Object getTestClassInstance() {
        return fixedInstance;
      }
    };
  }

  /** Invoked before the first execution of the fuzz target. */
  void beforeFirstExecution() throws Throwable;

  /**
   * Invoked before each execution of the fuzz target.
   *
   * <p>This is invoked after {@link #beforeFirstExecution()} for the first execution.
   */
  void beforeEachExecution() throws Throwable;

  void afterEachExecution() throws Throwable;

  /**
   * Invoked after the last execution of the fuzz target, regardless of whether there was a finding.
   */
  void afterLastExecution() throws Throwable;

  Object getTestClassInstance();

  @FunctionalInterface
  interface ThrowingRunnable {
    void run() throws Throwable;
  }
}
