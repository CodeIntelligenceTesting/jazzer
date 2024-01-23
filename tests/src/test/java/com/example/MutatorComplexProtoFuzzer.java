/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.protobuf.Proto2.TestProtobuf;

public class MutatorComplexProtoFuzzer {
  public static void fuzzerTestOneInput(@NotNull TestProtobuf proto) {
    if (proto.getI32() == 1234 && proto.getStr().equals("abcd")) {
      throw new FuzzerSecurityIssueMedium("Secret proto is found!");
    }
  }
}
