/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Verifies that reproducing a single input works for @FuzzTests. */
class JUnitReproducerTest {
  // echo "Hello, Jazzer!" | openssl dgst -binary -sha256 | openssl base64 -A
  private static final byte[] TARGET_DIGEST =
      Base64.getDecoder().decode("DmvypT3h1z31A1sD0XebOUmjn0QHsCvjGPOjYdRwG8Q=");

  public static Stream<Arguments> fuzzTest() {
    return Stream.of(arguments("Bye, Jazzer!".getBytes(StandardCharsets.UTF_8)));
  }

  @MethodSource
  @FuzzTest
  void fuzzTest(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    // This check is impossible for the fuzzer to crack - the exception will only be thrown when the
    // fuzz test is executed on the given seed.
    if (MessageDigest.isEqual(digest.digest(data), TARGET_DIGEST)) {
      throw new FuzzerSecurityIssueCritical("Digest found!");
    }
  }
}
