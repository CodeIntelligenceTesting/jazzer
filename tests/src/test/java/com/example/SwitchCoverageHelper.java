/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
