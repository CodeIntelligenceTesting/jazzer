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

package test;

import java.nio.charset.Charset;
import java.util.ArrayList;

final class ModifiedUtf8Encoder {
  // Encodes a string in the JVM's modified UTF-8 encoding.
  public static byte[] encode(String value) {
    // Modified UTF-8 is almost the same as CESU-8, the only difference being that the zero
    // character is coded on two bytes.
    byte[] cesuBytes = value.getBytes(Charset.forName("CESU-8"));
    ArrayList<Byte> modifiedUtf8Bytes = new ArrayList<>();
    for (byte cesuByte : cesuBytes) {
      if (cesuByte != 0) {
        modifiedUtf8Bytes.add(cesuByte);
      } else {
        modifiedUtf8Bytes.add((byte) 0xC0);
        modifiedUtf8Bytes.add((byte) 0x80);
      }
    }
    byte[] out = new byte[modifiedUtf8Bytes.size()];
    for (int i = 0; i < modifiedUtf8Bytes.size(); i++) {
      out[i] = modifiedUtf8Bytes.get(i);
    }
    return out;
  }
}
