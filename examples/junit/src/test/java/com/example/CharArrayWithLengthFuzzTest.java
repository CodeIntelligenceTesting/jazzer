/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import java.nio.charset.Charset;

public class CharArrayWithLengthFuzzTest {
  @FuzzTest
  public void fuzzCharArray(char @NotNull @WithLength(max = 5) [] data) {
    String expression = new String(data);
    // Each '中' character is encoded using three bytes with CESU8. To satisfy this check, the
    // underlying CESU8-encoded byte array should have at least 15 bytes.
    if (expression.equals("中中中中中")) {
      assert expression.getBytes(Charset.forName("CESU-8")).length == 15;
      throw new RuntimeException("Found evil code");
    }
  }
}
