/*
 * Copyright 2022 Code Intelligence GmbH
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.stream.Collectors;

final class ReproducerTemplates {
  private static final String rawBytesInput =
      "byte[] input = java.util.Base64.getDecoder().decode(base64Bytes);";
  private static final String fuzzedDataProviderInput =
      "com.code_intelligence.jazzer.api.CannedFuzzedDataProvider input = new com.code_intelligence.jazzer.api.CannedFuzzedDataProvider(base64Bytes);";

  public static void dumpReproducer(
      String base64, String dataSha, String targetClass, boolean useFuzzedDataProvider) {
    String targetArg = useFuzzedDataProvider ? fuzzedDataProviderInput : rawBytesInput;
    String template = new BufferedReader(
        new InputStreamReader(ReproducerTemplates.class.getResourceAsStream("Reproducer.java.tmpl"),
            StandardCharsets.UTF_8))
                          .lines()
                          .collect(Collectors.joining("\n"));
    String javaSource = String.format(template, dataSha, base64, targetClass, targetArg);
    Path javaPath = Paths.get(Opt.reproducerPath, String.format("Crash_%s.java", dataSha));
    try {
      Files.write(javaPath, javaSource.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
    } catch (IOException e) {
      System.err.printf("ERROR: Failed to write Java reproducer to %s%n", javaPath);
      e.printStackTrace();
    }
    System.out.printf(
        "reproducer_path='%s'; Java reproducer written to %s%n", Opt.reproducerPath, javaPath);
  }
}
