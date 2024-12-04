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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.SimpleArgumentConverter;
import org.junit.jupiter.params.provider.ValueSource;

class JavaBinarySeedFuzzTest {
  // Generated via:
  // printf 'tH15_1S-4_53Cr3T.fl4G' | openssl dgst -binary -sha256 | openssl base64 -A
  // Luckily the fuzzer can't read comments ;-)
  private static final byte[] FLAG_SHA256 =
      Base64.getDecoder().decode("q0vPdz5oeJIW3k2U4VJ+aWDufzzZbKAcevc9cNoUTSM=");

  static class Utf8BytesConverter extends SimpleArgumentConverter {
    @Override
    protected Object convert(Object source, Class<?> targetType)
        throws ArgumentConversionException {
      assertEquals(byte[].class, targetType);
      assertTrue(source instanceof byte[] || source instanceof String);
      if (source instanceof byte[]) {
        return source;
      }
      return ((String) source).getBytes(UTF_8);
    }
  }

  @ValueSource(strings = {"red herring", "tH15_1S-4_53Cr3T.fl4Ga"})
  @FuzzTest
  void fuzzTheFlag(@ConvertWith(Utf8BytesConverter.class) byte[] bytes)
      throws NoSuchAlgorithmException {
    assumeTrue(bytes.length > 0);
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(bytes, 0, bytes.length - 1);
    byte[] hash = digest.digest();
    byte secret = bytes[bytes.length - 1];
    if (MessageDigest.isEqual(hash, FLAG_SHA256) && secret == 's') {
      throw new Error("Fl4g 4nd s3cr3et f0und!");
    }
  }
}
