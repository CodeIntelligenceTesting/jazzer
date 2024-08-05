/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;

import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.google.protobuf.ByteString;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;

final class ByteStringMutatorFactory extends MutatorFactory {
  ByteStringMutatorFactory() {}

  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return findFirstParentIfClass(type, ByteString.class)
        .flatMap(parent -> factory.tryCreate(notNull(asAnnotatedType(byte[].class))))
        .map(
            byteArrayMutator ->
                mutateThenMapToImmutable(
                    (SerializingMutator<byte[]>) byteArrayMutator,
                    ByteString::copyFrom,
                    ByteString::toByteArray));
  }
}
