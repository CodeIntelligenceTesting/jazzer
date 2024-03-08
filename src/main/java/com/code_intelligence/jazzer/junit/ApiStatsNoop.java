/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

public class ApiStatsNoop implements ApiStats {
  @Override
  public void addStat(String endpointUri, String method, int responseStatusCode) {}

  @Override
  public String stringify() {
    return "";
  }
}
