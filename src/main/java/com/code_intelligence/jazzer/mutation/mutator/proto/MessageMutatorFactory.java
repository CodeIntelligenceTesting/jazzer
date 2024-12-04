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
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;

import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.lang.reflect.AnnotatedType;
import java.util.Optional;

public final class MessageMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType messageType, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(messageType, Message.class)
        .flatMap(TypeLibrary::getBuilderType)
        .flatMap(
            builderType ->
                // Forward the annotations (e.g. @NotNull) on the Message type to the Builder type.
                factory.tryCreateInPlace(
                    withExtraAnnotations(builderType, messageType.getAnnotations())))
        .map(
            builderMutator ->
                mutateThenMapToImmutable(
                    (SerializingMutator<Builder>) builderMutator,
                    Builder::build,
                    Message::toBuilder));
  }
}
