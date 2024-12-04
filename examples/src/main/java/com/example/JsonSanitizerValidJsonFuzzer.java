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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.json.JsonSanitizer;

public class JsonSanitizerValidJsonFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    String validJson;
    try {
      validJson = JsonSanitizer.sanitize(input, 10);
    } catch (Exception e) {
      return;
    }

    // Check that the output is valid JSON. Invalid JSON may crash other parts of the application
    // that trust the output of the sanitizer.
    try {
      Gson gson = new Gson();
      gson.fromJson(validJson, JsonElement.class);
    } catch (Exception e) {
      throw new FuzzerSecurityIssueLow("Output is invalid JSON", e);
    }
  }
}
