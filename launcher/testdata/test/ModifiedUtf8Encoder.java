/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
