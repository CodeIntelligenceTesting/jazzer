/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

public class SwitchCoverageHelper {
  int covered = 0;
  final int cases;
  static boolean[] casesVisited;

  public SwitchCoverageHelper(int cases) {
    this.cases = cases;
    casesVisited = new boolean[cases];
  }

  public void coverCase(int caze) {
    if (caze < 0 || caze >= cases) {
      throw new IllegalArgumentException("Invalid case");
    }
    if (casesVisited[caze]) {
      return;
    }
    casesVisited[caze] = true;
    covered++;
  }

  public boolean allBranchesCovered() {
    return covered == cases;
  }
}
