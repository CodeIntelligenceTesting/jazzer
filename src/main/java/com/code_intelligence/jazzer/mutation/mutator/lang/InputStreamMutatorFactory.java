/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
