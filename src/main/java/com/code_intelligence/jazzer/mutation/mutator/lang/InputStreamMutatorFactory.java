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

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;
import java.util.function.Predicate;

final class InputStreamMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {

    AnnotatedType innerByteArray = notNull(new TypeHolder<byte[]>() {}.annotatedType());

    return asSubclassOrEmpty(type, InputStream.class)
        .flatMap(parent -> LibFuzzerMutatorFactory.tryCreate(innerByteArray))
        .map(
            byteArrayMutator ->
                mutateThenMap(
                    (SerializingMutator<byte[]>) byteArrayMutator,
                    MutatorByteArrayInputStream::new,
                    MutatorByteArrayInputStream::getBuf,
                    (Predicate<Debuggable> inCycle) -> "InputStream"));
  }

  private static class MutatorByteArrayInputStream extends ByteArrayInputStream {
    private final byte[] buf;

    public MutatorByteArrayInputStream(byte[] buf) {
      super(buf);
      this.buf = buf;
    }

    public byte[] getBuf() {
      return buf;
    }
  }
}
