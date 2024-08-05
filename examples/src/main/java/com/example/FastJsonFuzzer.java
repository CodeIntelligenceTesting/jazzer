/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

// Found the issues described in
// https://github.com/alibaba/fastjson/issues/3631
public class FastJsonFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      JSON.parse(data.consumeRemainingAsString());
    } catch (JSONException ignored) {
    }
  }
}
