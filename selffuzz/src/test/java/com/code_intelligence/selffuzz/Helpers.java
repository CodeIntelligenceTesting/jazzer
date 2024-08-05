/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.selffuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.code_intelligence.selffuzz.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.engine.SeededPseudoRandom;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Helpers {
  public static <T> void assertMutator(SerializingMutator<T> mutator, byte[] data, long seed)
      throws IOException {
    PseudoRandom prng = new SeededPseudoRandom(seed);
    T read = mutator.readExclusive(new ByteArrayInputStream(data));
    T mutated = mutator.mutate(read, prng);
    T inited = mutator.init(prng);
    T crossedOver = mutator.crossOver(mutated, inited, prng);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    mutator.write(crossedOver, new DataOutputStream(out));
    T deserialized = mutator.read(new DataInputStream(new ByteArrayInputStream(out.toByteArray())));

    assertEquals(crossedOver, deserialized);
  }
}
