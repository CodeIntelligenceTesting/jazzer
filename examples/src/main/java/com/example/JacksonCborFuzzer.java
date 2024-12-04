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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.io.IOException;

// Reproduces https://github.com/FasterXML/jackson-dataformats-binary/issues/236 and
// https://github.com/FasterXML/jackson-databind/pull/3032 if executed with
// `--keep_going=3 -seed=2735196724`.
public class JacksonCborFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    CBORFactory factory = new CBORFactory();
    ObjectMapper mapper = new ObjectMapper(factory);
    mapper.enableDefaultTyping();
    try {
      mapper.readTree(input);
    } catch (IOException ignored) {
    }
  }
}
