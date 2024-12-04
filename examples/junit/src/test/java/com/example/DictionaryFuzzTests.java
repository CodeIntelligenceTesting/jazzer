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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.DictionaryEntries;
import com.code_intelligence.jazzer.junit.DictionaryFile;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DictionaryFuzzTests {
  // Generated via:
  // printf 'a_53Cr"3T_fl4G' | openssl dgst -binary -sha256 | openssl base64 -A
  // Luckily the fuzzer can't read comments ;-)
  private static final byte[] FLAG_SHA256 =
      Base64.getDecoder().decode("vCLInoVuMxJonT4UKjsMl0LPXTowkYS7t0uBpw0pRo8=");

  @DictionaryEntries({"a_", "53Cr\"3T_", "fl4G"})
  @FuzzTest
  public void inlineTest(FuzzedDataProvider data)
      throws NoSuchAlgorithmException, TestSuccessfulException {
    String s = data.consumeRemainingAsString();
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, FLAG_SHA256)) {
      throw new TestSuccessfulException("error found");
    }
  }

  @DictionaryFile(resourcePath = "test.dict")
  @FuzzTest
  public void fileTest(FuzzedDataProvider data)
      throws NoSuchAlgorithmException, TestSuccessfulException {
    String s = data.consumeRemainingAsString();
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, FLAG_SHA256)) {
      throw new TestSuccessfulException("error found");
    }
  }

  @DictionaryEntries("a_")
  @DictionaryFile(resourcePath = "test2.dict")
  @DictionaryFile(resourcePath = "/com/example/test3.dict")
  @FuzzTest
  public void mixedTest(FuzzedDataProvider data)
      throws NoSuchAlgorithmException, TestSuccessfulException {
    String s = data.consumeRemainingAsString();
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    if (MessageDigest.isEqual(hash, FLAG_SHA256)) {
      throw new TestSuccessfulException("error found");
    }
  }
}
