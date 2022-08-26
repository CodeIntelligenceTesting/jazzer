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

import com.code_intelligence.jazzer.agent.AgentInstaller;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;

class RegressionTestExtensions
    implements BeforeEachCallback, AfterEachCallback, InvocationInterceptor {
  private static Field lastFindingField;

  @Override
  public void beforeEach(ExtensionContext extensionContext) {
    // These methods are idempotent, so there is no need to synchronize.
    AgentConfigurator.configure(extensionContext);
    AgentInstaller.install(true);
  }

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

  @Override
  public void afterEach(ExtensionContext extensionContext) {
    extensionContext.publishReportEntry(
        "No fuzzing has been performed, the fuzz test has only been executed on the fixed set of inputs in the "
        + "seed corpus.\n"
        + "To start fuzzing, run a test with the environment variable JAZZER_FUZZ set to a non-empty value.");
  }

  private static Field getLastFindingField() throws Throwable {
    if (lastFindingField == null) {
      Class<?> jazzerInternal =
          Class.forName("com.code_intelligence.jazzer.runtime.JazzerInternal");
      lastFindingField = jazzerInternal.getField("lastFinding");
    }
    return lastFindingField;
  }
}
