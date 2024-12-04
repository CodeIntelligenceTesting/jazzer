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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class PCharGenerator {
  public static void main(String[] args) {
    byte[] VALID_PCHAR =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:@!$&'()*+,;="
            .getBytes(StandardCharsets.UTF_8);
    Arrays.sort(VALID_PCHAR);
    byte[] lut = new byte[256];
    int idx = 0;
    for (int i = 0; i < 256; i++) {
      if (Arrays.binarySearch(VALID_PCHAR, (byte) i) >= 0) {
        lut[i] = (byte) i;
      } else {
        lut[i] = VALID_PCHAR[idx];
        idx = (idx + 1) % VALID_PCHAR.length;
      }
    }
    for (byte b : lut) {
      System.out.print((char) b);
    }
  }
}
