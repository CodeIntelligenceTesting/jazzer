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

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;

class RegressionTestExtensions implements InvocationInterceptor, ExecutionCondition {
  private static final boolean DISABLE_FOR_FUZZING =
      System.getenv("JAZZER_FUZZ") != null && !System.getenv("JAZZER_FUZZ").isEmpty();
  private static Field lastFindingField;

  @Override
  public void interceptTestTemplateMethod(Invocation<Void> invocation,
      ReflectiveInvocationContext<Method> invocationContext, ExtensionContext extensionContext)
      throws Throwable {
    // Mimics the logic of Jazzer's FuzzTargetRunner, which reports findings in the following way:
    // 1. If a hook used Jazzer#reportFindingFromHook to explicitly report a finding, the last such
    //    finding, as stored in JazzerInternal#lastFinding, is reported.
    // 2. Otherwise, if the fuzz target method threw a Throwable, that is reported.
    // 3. Otherwise, nothing is reported.
    Throwable thrown = null;
    getLastFindingField().set(null, null);
    try {
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

  private static Field getLastFindingField() throws Throwable {
    if (lastFindingField == null) {
      Class<?> jazzerInternal =
          Class.forName("com.code_intelligence.jazzer.runtime.JazzerInternal");
      lastFindingField = jazzerInternal.getField("lastFinding");
    }
    return lastFindingField;
  }

  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
    // Some IDEs use junit.jupiter.conditions.deactivate to run tests marked with @Disabled, e.g.
    // when a particular test method is requested. However, since the agent can currently only be
    // configured once, we must not let this happen and thus implement our own disabling condition.
    // https://junit.org/junit5/docs/current/user-guide/#extensions-conditions-deactivation
    if (DISABLE_FOR_FUZZING) {
      return ConditionEvaluationResult.disabled(
          "Regression tests are disabled while fuzzing is enabled with a non-empty value for the JAZZER_FUZZ environment variable");
    } else {
      return ConditionEvaluationResult.enabled(
          "Regression tests are run instead of fuzzing since JAZZER_FUZZ has not been set to a non-empty value");
    }
  }
}
