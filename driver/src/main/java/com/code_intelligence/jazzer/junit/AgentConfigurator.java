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

import static com.code_intelligence.jazzer.sanitizers.Constants.SANITIZER_HOOK_NAMES;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.extension.ExtensionContext;

class AgentConfigurator {
  private static final AtomicBoolean hasBeenConfigured = new AtomicBoolean();

  static void configure(ExtensionContext extensionContext) {
    if (!hasBeenConfigured.compareAndSet(false, true)) {
      return;
    }

    // Apply all hooks, but no coverage or compare instrumentation.
    System.setProperty("jazzer.instrumentation_excludes", "**");
    System.setProperty("jazzer.custom_hooks", SANITIZER_HOOK_NAMES);
    extensionContext.getConfigurationParameter("jazzer.instrument")
        .ifPresent(s
            -> System.setProperty(
                "jazzer.custom_hook_includes", String.join(File.pathSeparator, s.split(","))));
    // Do not hook common IDE and JUnit classes and their dependencies.
    System.setProperty("jazzer.custom_hook_excludes",
        String.join(File.pathSeparator, "com.google.testing.junit.**", "com.intellij.**",
            "io.github.classgraph.**", "junit.framework.**", "net.bytebuddy.**",
            "org.apiguardian.**", "org.assertj.core.**", "org.hamcrest.**", "org.junit.**",
            "org.opentest4j.**"));
  }
}
