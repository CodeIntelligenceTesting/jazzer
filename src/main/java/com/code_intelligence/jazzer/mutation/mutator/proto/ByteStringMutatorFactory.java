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

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.ByteString;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;

final class ByteStringMutatorFactory implements MutatorFactory {
  ByteStringMutatorFactory() {}

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return findFirstParentIfClass(type, ByteString.class)
        .flatMap(parent -> factory.tryCreate(notNull(new TypeHolder<byte[]>() {}.annotatedType())))
        .map(
            byteArrayMutator ->
                mutateThenMapToImmutable(
                    (SerializingMutator<byte[]>) byteArrayMutator,
                    ByteString::copyFrom,
                    ByteString::toByteArray));
  }
}
