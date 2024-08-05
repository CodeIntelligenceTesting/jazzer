/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
