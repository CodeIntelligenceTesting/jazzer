/*
 * Copyright 2022 Code Intelligence GmbH
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
import com.code_intelligence.jazzer.api.Jazzer;

public class JazzerApiFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Jazzer.exploreState(data.consumeByte(), 1);
    Jazzer.guideTowardsEquality(data.consumeString(10), data.pickValue(new String[] {"foo"}), 1);
    Jazzer.guideTowardsEquality(data.consumeBytes(10), new byte[] {}, 2);
    Jazzer.guideTowardsContainment(data.consumeAsciiString(10), "bar", 2);
    throw new FuzzerSecurityIssueLow("Jazzer API calls succeed");
  }
}
