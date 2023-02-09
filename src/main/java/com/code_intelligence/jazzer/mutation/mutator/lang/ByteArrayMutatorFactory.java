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

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.readAllBytes;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.google.errorprone.annotations.Immutable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.AnnotatedType;
import java.util.Arrays;
import java.util.Optional;

final class ByteArrayMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return findFirstParentIfClass(type, byte[].class).map(parent -> ByteArrayMutator.INSTANCE);
  }

  @Immutable
  private static final class ByteArrayMutator implements SerializingMutator<byte[]> {
    private static final ByteArrayMutator INSTANCE = new ByteArrayMutator();

    private ByteArrayMutator() {}

    @Override
    public byte[] read(DataInputStream in) throws IOException {
      byte[] bytes = new byte[in.readInt()];
      in.readFully(bytes);
      return bytes;
    }

    @Override
    public byte[] readExclusive(InputStream in) throws IOException {
      return readAllBytes(in);
    }

    @Override
    public void write(byte[] value, DataOutputStream out) throws IOException {
      out.writeInt(value.length);
      out.write(value);
    }

    @Override
    public void writeExclusive(byte[] value, OutputStream out) throws IOException {
      out.write(value);
    }

    @Override
    public byte[] detach(byte[] value) {
      return Arrays.copyOf(value, value.length);
    }

    @Override
    public byte[] init(PseudoRandom prng) {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public byte[] mutate(byte[] value, PseudoRandom prng) {
      throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public String toString() {
      return "ByteArray";
    }
  }
}
