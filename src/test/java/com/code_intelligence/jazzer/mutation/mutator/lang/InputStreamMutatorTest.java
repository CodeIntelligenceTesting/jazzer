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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutate;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InputStreamMutatorTest {
  ChainedMutatorFactory factory;

  @BeforeEach
  void createFactory() {
    factory = ChainedMutatorFactory.of(LangMutators.newFactories());
  }

  @AfterEach
  void cleanMockSize() {
    System.clearProperty(LibFuzzerMutate.MOCK_SIZE_KEY);
  }

  @Test
  void testInputStreamMutator() throws IOException {
    SerializingMutator<InputStream> mutator =
        (SerializingMutator<InputStream>)
            factory.createOrThrow(new TypeHolder<@NotNull InputStream>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("InputStream");

    PseudoRandom prng = anyPseudoRandom();

    InputStream inited = mutator.init(prng);
    assertThat(inited).isNotNull();

    InputStream mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);

    InputStream detached = mutator.detach(mutated);
    assertThat(detached).isNotEqualTo(mutated);

    byte[] initedData = readAll(inited);
    byte[] mutatedData = readAll(mutated);
    byte[] detachedData = readAll(detached);
    assertThat(initedData).isNotEqualTo(mutatedData);
    assertThat(mutatedData).isEqualTo(detachedData);
  }

  private static byte[] readAll(InputStream inited) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[4];
    while ((nRead = inited.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    buffer.flush();
    return buffer.toByteArray();
  }
}
