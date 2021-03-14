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

// Verify that overly broad catch clauses do not prevent exceptions of type FuzzerSecurityIssue*
// from propagating upwards.
public class RethrowFuzzerSecurityIssueTest {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      try {
        throw new OutOfMemoryError("Should be caught");
      } catch (Throwable t) {
        try {
          // Throws a FuzzerSecurityIssueCritical, which should not be caught by subsequent catch
          // clauses.
          mustNeverBeCalled();
        } catch (Throwable ignored) {
          // Special case for instrumentation: new at the beginning of exception handler.
          new Object();
        }
      }
    } catch (Error ignored) {
    }
  }

  private static void mustNeverBeCalled() {
    // Throws FuzzerSecurityIssueCritical via a hook in UncatchableFuzzerSecurityIssuesHooks.
  }
}
