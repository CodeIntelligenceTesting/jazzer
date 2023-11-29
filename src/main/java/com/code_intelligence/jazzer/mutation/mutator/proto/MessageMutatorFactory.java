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
