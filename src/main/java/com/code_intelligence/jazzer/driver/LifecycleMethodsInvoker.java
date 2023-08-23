/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.driver;

/**
 * Can provide callbacks to be invoked by {@link FuzzTargetRunner} at certain times during the
 * execution of a fuzz target.
 */
public interface LifecycleMethodsInvoker {

  /**
   * An implementation of {@link LifecycleMethodsInvoker} with empty implementations.
   */
  LifecycleMethodsInvoker NOOP = new LifecycleMethodsInvoker() {
    @Override
    public void beforeFirstExecution() {
    }

    @Override
    public void beforeEachExecution() {
    }

    @Override
    public void afterLastExecution() {
    }
  };

  /**
   * Invoked before the first execution of the fuzz target.
   */
  void beforeFirstExecution() throws Throwable;

  /**
   * Invoked before each execution of the fuzz target.
   *
   * <p>This is invoked after {@link #beforeFirstExecution()} for the first execution.
   */
  void beforeEachExecution() throws Throwable;

  /**
   * Invoked after the last execution of the fuzz target, regardless of whether there was a
   * finding.
   */
  void afterLastExecution() throws Throwable;

  interface ThrowingRunnable {
    void run() throws Throwable;
  }
}
