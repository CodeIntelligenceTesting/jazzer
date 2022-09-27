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

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;

class AutofuzzFuzzTest {
  private static class IntHolder {
    private final int i;

    IntHolder(int i) {
      this.i = i;
    }

    public int getI() {
      return i;
    }
  }

  @FuzzTest(maxDuration = "5m")
  void autofuzz(String str, IntHolder holder) {
    assumeTrue(holder != null);
    if (holder.getI() == 1234 && str != null && str.contains("jazzer")) {
      throw new RuntimeException();
    }
  }
}
