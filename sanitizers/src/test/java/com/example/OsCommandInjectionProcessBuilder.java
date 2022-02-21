// Copyright 2021 Code Intelligence GmbH
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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.concurrent.TimeUnit;

public class OsCommandInjectionProcessBuilder {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsAsciiString();
    try {
      ProcessBuilder processBuilder = new ProcessBuilder(input);
      processBuilder.environment().clear();
      Process process = processBuilder.start();
      // This should be way faster, but we have to wait until the call is done
      if (!process.waitFor(10, TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
      }
    } catch (Exception ignored) {
      // Ignore execution and setup exceptions
    }
  }
}
