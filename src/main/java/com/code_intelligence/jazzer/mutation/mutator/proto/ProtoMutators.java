/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.proto;

import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;

public final class ProtoMutators {
  private ProtoMutators() {}

  public static MutatorFactory newFactory() {
    try {
      Class.forName("com.google.protobuf.Message");
      return new ChainedMutatorFactory(
          new ByteStringMutatorFactory(), new MessageMutatorFactory(), new BuilderMutatorFactory());
    } catch (ClassNotFoundException e) {
      return new ChainedMutatorFactory();
    }
  }
}
