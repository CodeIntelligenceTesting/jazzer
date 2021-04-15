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

package com.code_intelligence.jazzer.runtime;

final public class JazzerInternal {
  // Accessed from native code.
  private static Throwable lastFinding;

  // Accessed from api.Jazzer via reflection.
  public static void reportFindingFromHook(Throwable finding) {
    lastFinding = finding;
    // Throw an Error that is hard to catch (short of outright ignoring it) in order to quickly
    // terminate the execution of the fuzz target. The finding will be reported as soon as the fuzz
    // target returns even if this Error is swallowed.
    throw new HardToCatchError();
  }
}
