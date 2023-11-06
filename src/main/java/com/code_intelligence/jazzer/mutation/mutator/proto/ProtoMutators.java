/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.proto;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import java.util.stream.Stream;

public final class ProtoMutators {
  private ProtoMutators() {}

  public static Stream<MutatorFactory> newFactories() {
    try {
      Class.forName("com.google.protobuf.Message");
      return Stream.of(
          new ByteStringMutatorFactory(), new MessageMutatorFactory(), new BuilderMutatorFactory());
    } catch (ClassNotFoundException e) {
      return Stream.empty();
    }
  }
}
