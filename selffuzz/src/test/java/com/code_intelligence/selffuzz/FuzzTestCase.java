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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

class FuzzTestCase {
  @FuzzTest(maxDuration = "10m")
  void stringMutatorTest(byte[] data) {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<String>() {}.annotatedType());
    if (data.length < 3) {
      return;
    }

    InputStream i = new ByteArrayInputStream(data);
    DataInputStream stream = new DataInputStream(i);

    try {
      String out = mutator.read(stream);
    } catch (EOFException e) {
      // ignore end of file exceptions which can happen due to an invalid length in the input byte
      // array
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
