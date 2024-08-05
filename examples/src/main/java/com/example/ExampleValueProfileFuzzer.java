/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.util.Base64;

public class ExampleValueProfileFuzzer {
  private static String base64(byte[] input) {
    return Base64.getEncoder().encodeToString(input);
  }

  private static long insecureEncrypt(long input) {
    long key = 0xefe4eb93215cb6b0L;
    return input ^ key;
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Without -use_value_profile=1, the fuzzer gets stuck here as there is no direct correspondence
    // between the input bytes and the compared string. With value profile, the fuzzer can guess the
    // expected input byte by byte, which takes linear rather than exponential time.
    if (((Object) base64(data.consumeBytes(6))).equals("SmF6emVy")) {
      long[] plaintextBlocks = data.consumeLongs(2);
      if (plaintextBlocks.length != 2) return;
      if (insecureEncrypt(plaintextBlocks[0]) == 0x9fc48ee64d3dc090L) {
        // Without variants of the fuzzer hooks for compares that also take in fake PCs, the fuzzer
        // would get stuck here as the value profile information for long comparisons would not be
        // able to distinguish between this comparison and the one above.
        if (insecureEncrypt(plaintextBlocks[1]) == 0x888a82ff483ad9c2L) {
          mustNeverBeCalled();
        }
      }
    }
  }

  private static void mustNeverBeCalled() {
    throw new FuzzerSecurityIssueLow("mustNeverBeCalled has been called");
  }
}
