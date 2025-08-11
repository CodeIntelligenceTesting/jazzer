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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class FuzzTestWithCrashTest {
  @FuzzTest(maxDuration = "10s")
  void crashFuzz(FuzzedDataProvider d) {
    String input = d.consumeRemainingAsString();
    if (Objects.equals(input, "crash")) {
      byte[] bytes =
          new byte[] {
            0xa, 0x5c, 0x45, 0x5d, 0x5c, 0x45, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d,
          };
      String data = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
      try {
        Pattern.matches("\\Q" + data + "\\E", "foobar");
      } catch (PatternSyntaxException ignored) {
      }
    }
  }
}
