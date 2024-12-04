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
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

public class MutatorFuzzer {
  public static void fuzzerTestOneInput(
      @InRange(max = -42) short num, @NotNull SimpleProto.MyProto proto) {
    if (num > -42) {
      throw new IllegalArgumentException();
    }

    if (proto.getNumber() == 12345678) {
      if (proto.getMessage().getText().contains("Hello, proto!")) {
        throw new FuzzerSecurityIssueMedium("Dangerous proto");
      }
    }
  }
}
