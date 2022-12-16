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

package com.code_intelligence.jazzer.instrumentor;

/**
 * Helper interface used to call methods on instances of AfterHooksTarget classes loaded via
 * different class loaders.
 */
public interface AfterHooksTargetContract extends DynamicTestContract {
  void registerHasFunc1BeenCalled();

  void verifyFirstSecret(String secret);

  void verifySecondSecret(String secret);

  void verifyThirdSecret(String secret);
}
