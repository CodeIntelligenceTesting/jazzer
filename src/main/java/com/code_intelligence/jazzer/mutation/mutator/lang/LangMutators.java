/*
 * Copyright 2023 Code Intelligence GmbH
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

import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;

public final class LangMutators {
  private LangMutators() {}

  public static MutatorFactory newFactory() {
    return new ChainedMutatorFactory(new NullableMutatorFactory(), new BooleanMutatorFactory(),
        new FloatingPointMutatorFactory(), new IntegralMutatorFactory(),
        new ByteArrayMutatorFactory(), new StringMutatorFactory(), new EnumMutatorFactory());
  }
}
