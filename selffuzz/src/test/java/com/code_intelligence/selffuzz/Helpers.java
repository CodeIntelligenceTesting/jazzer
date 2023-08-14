/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.selffuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.code_intelligence.selffuzz.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.engine.SeededPseudoRandom;
import com.code_intelligence.selffuzz.jazzer.mutation.support.InputStreamSupport;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class Helpers {
  public static <T> void assertMutator(SerializingMutator<T> mutator, byte[] data, long seed)
      throws IOException {
    PseudoRandom prng = new SeededPseudoRandom(seed);
    try (DataInputStream stream = infiniteByteStream(data)) {
      T read = mutator.read(stream);
      T mutated = mutator.mutate(read, prng);
      T inited = mutator.init(prng);
      T crossedOver = mutator.crossOver(mutated, inited, prng);

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      mutator.write(crossedOver, new DataOutputStream(out));
      T deserialized =
          mutator.read(new DataInputStream(new ByteArrayInputStream(out.toByteArray())));

      assertEquals(crossedOver, deserialized);
    }
  }

  private static DataInputStream infiniteByteStream(byte[] data) {
    InputStream dataStream = new ByteArrayInputStream(data);
    return new DataInputStream(InputStreamSupport.extendWithZeros(dataStream));
  }
}
