/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
