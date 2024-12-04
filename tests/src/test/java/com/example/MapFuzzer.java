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

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.util.Map;

public class MapFuzzer {
  public static void fuzzerTestOneInput(@NotNull Map<@NotNull String, @NotNull String> map) {
    if (map.getOrDefault("some_key", "").startsWith("prefix")) {
      if (map.containsKey("other_key")) {
        throw new FuzzerSecurityIssueMedium();
      }
    }
  }
}
