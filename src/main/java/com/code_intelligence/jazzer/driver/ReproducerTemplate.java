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

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.utils.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.stream.Collectors;

final class ReproducerTemplate {
  // A constant pool CONSTANT_Utf8_info entry should be able to hold data of size
  // uint16, but somehow this does not seem to be the case and leads to invalid
  // code crash reproducer code. Reducing the size by one resolves the problem.
  private static final int DATA_CHUNK_MAX_LENGTH = Short.MAX_VALUE - 1;
  private static final String RAW_BYTES_INPUT =
      "byte[] input = java.util.Base64.getDecoder().decode(base64Bytes);";
  private static final String FUZZED_DATA_PROVIDER_INPUT =
      "com.code_intelligence.jazzer.api.CannedFuzzedDataProvider input = new"
          + " com.code_intelligence.jazzer.api.CannedFuzzedDataProvider(base64Bytes);";

  private final String targetClass;
  private final boolean useFuzzedDataProvider;

  public ReproducerTemplate(String targetClass, boolean useFuzzedDataProvider) {
    this.targetClass = targetClass;
    this.useFuzzedDataProvider = useFuzzedDataProvider;
  }

  /**
   * Emits a Java reproducer to {@code Crash_HASH.java} in {@code Opt.reproducerPath}.
   *
   * @param data the Base64-encoded data to emit as a string literal
   * @param sha the SHA1 hash of the raw fuzzer input
   */
  public void dumpReproducer(String data, String sha) {
    String targetArg = useFuzzedDataProvider ? FUZZED_DATA_PROVIDER_INPUT : RAW_BYTES_INPUT;
    String template =
        new BufferedReader(
                new InputStreamReader(
                    ReproducerTemplate.class.getResourceAsStream("Reproducer.java.tmpl"),
                    StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"));
    String chunkedData = chunkStringLiteral(data);
    String javaSource = String.format(template, sha, chunkedData, targetClass, targetArg);
    Path javaPath = Paths.get(Opt.reproducerPath.get(), String.format("Crash_%s.java", sha));
    try {
      Files.write(javaPath, javaSource.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      Log.error(String.format("Failed to write Java reproducer to %s%n", javaPath));
      e.printStackTrace();
    }
    Log.println(
        String.format(
            "reproducer_path='%s'; Java reproducer written to %s%n",
            Opt.reproducerPath.get(), javaPath));
  }

  // The serialization of recorded FuzzedDataProvider invocations can get too long to be emitted
  // into the template as a single String literal. This is mitigated by chunking the data and
  // concatenating it again in the generated code.
  private String chunkStringLiteral(String data) {
    ArrayList<String> chunks = new ArrayList<>();
    for (int i = 0; i <= data.length() / DATA_CHUNK_MAX_LENGTH; i++) {
      chunks.add(
          data.substring(
              i * DATA_CHUNK_MAX_LENGTH, Math.min((i + 1) * DATA_CHUNK_MAX_LENGTH, data.length())));
    }
    return String.join("\", \"", chunks);
  }
}
