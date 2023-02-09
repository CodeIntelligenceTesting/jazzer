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

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.combine;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProperty;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateViaView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.getMessageField;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.getPresentFieldOrNull;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.makeMutableRepeatedFieldView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.makeMutableRepeatedMessageFieldView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.setFieldWithPresence;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.setMessageField;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.cap;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.check;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.Type;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class BuilderMutatorFactory extends MutatorFactory {
  private static <T extends Builder> Descriptor getDescriptor(Class<T> builderClass) {
    Method getDescriptor;
    try {
      getDescriptor = builderClass.getMethod("getDescriptor");
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    }
    Descriptor descriptor;
    try {
      descriptor = (Descriptor) getDescriptor.invoke(null);
    } catch (IllegalAccessException | InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
    return descriptor;
  }

  private static <T extends Builder, U> InPlaceMutator<T> mutatorForField(
      FieldDescriptor field, T fieldBuilder, MutatorFactory factory) {
    AnnotatedType typeToMutate = TypeLibrary.getTypeToMutate(field, fieldBuilder);
    requireNonNull(typeToMutate, () -> "Java class not specified for " + field);

    if (field.isRepeated()) {
      if (field.getType() == Type.MESSAGE) {
        InPlaceMutator<List<Builder>> underlyingMutator =
            (InPlaceMutator<List<Builder>>) factory.createInPlaceOrThrow(typeToMutate);
        return mutateViaView(
            builder -> makeMutableRepeatedMessageFieldView(builder, field), underlyingMutator);
      } else {
        InPlaceMutator<List<U>> underlyingMutator =
            (InPlaceMutator<List<U>>) factory.createInPlaceOrThrow(typeToMutate);
        return mutateViaView(
            builder -> makeMutableRepeatedFieldView(builder, field), underlyingMutator);
      }
    } else if (field.hasPresence()) {
      if (field.getType() == Type.MESSAGE) {
        ValueMutator<Builder> underlyingMutator =
            (ValueMutator<Builder>) factory.createOrThrow(typeToMutate);
        return mutateProperty(builder
            -> getMessageField(builder, field),
            underlyingMutator, (builder, value) -> setMessageField(builder, field, value));
      } else {
        ValueMutator<U> underlyingMutator = (ValueMutator<U>) factory.createOrThrow(typeToMutate);
        return mutateProperty(builder
            -> getPresentFieldOrNull(builder, field),
            underlyingMutator, (builder, value) -> setFieldWithPresence(builder, field, value));
      }
    } else {
      ValueMutator<U> underlyingMutator = (ValueMutator<U>) factory.createOrThrow(typeToMutate);
      return mutateProperty(builder
          -> (U) builder.getField(field),
          underlyingMutator, (builder, value) -> builder.setField(field, value));
    }
  }

  private static <T extends Builder> Supplier<T> makeBuilderSupplier(Class<T> builderClass) {
    Class<?> messageClass = builderClass.getEnclosingClass();
    Method newBuilder;
    try {
      newBuilder = messageClass.getMethod("newBuilder");
      check(Modifier.isStatic(newBuilder.getModifiers()));
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(
          format(
              "Message class for builder type %s does not have a newBuilder method", builderClass),
          e);
    }
    return () -> {
      try {
        return (T) newBuilder.invoke(null);
      } catch (IllegalAccessException | InvocationTargetException e) {
        throw new IllegalStateException(
            format(newBuilder + " isn't accessible or threw an exception"), e);
      }
    };
  }

  private static Serializer<Builder> makeBuilderSerializer(Supplier<Builder> supplier) {
    return new Serializer<Builder>() {
      @Override
      public Builder read(DataInputStream in) throws IOException {
        int length = in.readInt();
        return supplier.get().mergeFrom(cap(in, length));
      }

      @Override
      public void write(Builder builder, DataOutputStream out) throws IOException {
        Message message = builder.build();
        out.writeInt(message.getSerializedSize());
        message.writeTo(out);
      }

      @Override
      public Builder readExclusive(InputStream in) throws IOException {
        return supplier.get().mergeFrom(in);
      }

      @Override
      public void writeExclusive(Builder builder, OutputStream out) throws IOException {
        builder.build().writeTo(out);
      }

      @Override
      public Builder detach(Builder builder) {
        return builder.build().toBuilder();
      }
    };
  }

  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return asSubclassOrEmpty(type, Builder.class).map(builderClass -> {
      Supplier<Builder> builderSupplier = makeBuilderSupplier(builderClass);
      return combine(builderSupplier, makeBuilderSerializer(builderSupplier),
          getDescriptor(builderClass)
              .getFields()
              .stream()
              .map(fieldDescriptor
                  -> mutatorForField(fieldDescriptor, builderSupplier.get(), factory))
              .toArray(InPlaceMutator[] ::new));
    });
  }
}
