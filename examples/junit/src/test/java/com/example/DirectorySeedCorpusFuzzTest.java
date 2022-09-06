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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class DirectorySeedCorpusFuzzTest {
  private static long runs = 0;

  @FuzzTest(seedCorpus = "/com/example/DirectoryBasedSeedCorpus", maxDuration = "0s")
  public void seedCorpusFuzz(FuzzedDataProvider data) {
    if (runs++ > 1) {
      // Only execute the fuzz test logic on the empty input and the only seed.
      return;
    }
    if (data.consumeRemainingAsString().equals("directory")) {
      throw new FuzzerSecurityIssueMedium();
    }
  }
}
