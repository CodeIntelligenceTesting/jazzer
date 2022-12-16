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

package com.code_intelligence.jazzer.api;

// An exception wrapping a Throwable thrown during the construction of parameters for, but not the
// actual invocation of an autofuzzed method.
/**
 * Only used internally.
 */
public class AutofuzzConstructionException extends RuntimeException {
  public AutofuzzConstructionException() {
    super();
  }
  public AutofuzzConstructionException(String message) {
    super(message);
  }
  public AutofuzzConstructionException(Throwable cause) {
    super(cause);
  }
}
