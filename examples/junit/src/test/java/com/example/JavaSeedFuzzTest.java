/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static java.util.Arrays.asList;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JavaSeedFuzzTest {
  // Generated via:
  // printf 'tH15_1S-4_53Cr3T.fl4G' | openssl dgst -binary -sha256 | openssl base64 -A
  // Luckily the fuzzer can't read comments ;-)
  private static final byte[] FLAG_SHA256 =
      Base64.getDecoder().decode("q0vPdz5oeJIW3k2U4VJ+aWDufzzZbKAcevc9cNoUTSM=");

  static Stream<Arguments> fuzzTheFlag() {
    return Stream.of(
        arguments(asList("red", "herring"), 0),
        // This argument passes the hash check, but does not trigger the finding right away. This
        // is meant to verify that the seed ends up in the corpus, serving as the base for future
        // mutations rather than just being executed once.
        arguments(asList("tH15_1S", "-4_53Cr3T", ".fl4G"), 42));
  }

  @MethodSource
  @FuzzTest
  void fuzzTheFlag(@NotNull List<@NotNull String> flagParts, int secret)
      throws NoSuchAlgorithmException {
    byte[] hash =
        MessageDigest.getInstance("SHA-256")
            .digest(String.join("", flagParts).getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, FLAG_SHA256) && secret == 1337) {
      throw new Error("Fl4g 4nd s3cr3et f0und!");
    }
  }
}
