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
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Objects;

public class ObjectEqualsIntegerFuzzer {
  @FuzzTest
  void objectEqualsInteger(FuzzedDataProvider fdp) {
    int integer = fdp.consumeInt();
    if (Objects.equals(integer, 4711)) {
      throw new FuzzerSecurityIssueLow("ObjectsEqualsFuzzer works!");
    }
  }
}
