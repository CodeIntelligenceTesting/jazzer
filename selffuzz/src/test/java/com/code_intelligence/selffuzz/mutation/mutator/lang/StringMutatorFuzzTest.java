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

package com.code_intelligence.selffuzz.mutation.mutator.lang;

import static com.code_intelligence.selffuzz.Helpers.assertMutator;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;
import java.io.IOException;

@SuppressWarnings("unchecked")
class StringMutatorFuzzTest {
  @FuzzTest(maxDuration = "10m")
  void stringMutatorTest(long seed, byte @NotNull [] data) throws IOException {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>)
            Mutators.newFactory().createOrThrow(new TypeHolder<String>() {}.annotatedType());
    assertMutator(mutator, data, seed);
  }
}
