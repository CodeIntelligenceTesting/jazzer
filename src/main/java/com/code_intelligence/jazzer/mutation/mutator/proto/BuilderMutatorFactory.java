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

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.assemble;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.combine;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProperty;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateSumInPlace;
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
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.Type;
import com.google.protobuf.Descriptors.OneofDescriptor;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import com.google.protobuf.UnknownFieldSet;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

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
      FieldDescriptor field, T builderInstance, MutatorFactory factory) {
    AnnotatedType typeToMutate = TypeLibrary.getTypeToMutate(field, builderInstance);
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

  private static <T extends Builder> Stream<InPlaceMutator<T>> mutatorsForFields(
      Optional<OneofDescriptor> oneofField, List<FieldDescriptor> fields, T builderInstance,
      MutatorFactory factory) {
    if (oneofField.isPresent()) {
      // oneof fields are mutated as one as mutating them independently would cause the mutator to
      // erratically switch between the different states. The individual fields are kept in the
      // order in which they are defined in the .proto file.
      return Stream.of(mutateSumInPlace(
          (T builder)
              -> {
            FieldDescriptor setField = builder.getOneofFieldDescriptor(oneofField.get());
            if (setField == null) {
              return -1;
            } else {
              // The index of the field within the oneof is 1-based otherwise, so we need to
              // subtract 1 to fulfill the contract of mutateSumInPlace.
              return setField.getIndex() - 1;
            }
          },
          // Mutating to the unset (-1) state is handled by the individual field mutators, which
          // are created nullable as oneof fields report that they track presence.
          fields.stream()
              .map(field -> mutatorForField(field, builderInstance, factory))
              .toArray(InPlaceMutator[] ::new)));
    } else {
      // All non-oneof fields are mutated independently, using the order in which they are declared
      // in the .proto file (which may not coincide with the order by field number).
      return fields.stream().map(field -> mutatorForField(field, builderInstance, factory));
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
        int length = Math.max(in.readInt(), 0);
        return parseLeniently(cap(in, length));
      }

      @Override
      public Builder readExclusive(InputStream in) throws IOException {
        return parseLeniently(in);
      }

      private Builder parseLeniently(InputStream in) throws IOException {
        Builder builder = supplier.get();
        try {
          builder.mergeFrom(in);
        } catch (InvalidProtocolBufferException ignored) {
          // builder has been partially modified with what could be decoded before the parser error.
        }
        // We never want the fuzz test to see unknown fields and our mutations should never produce
        // them.
        builder.setUnknownFields(UnknownFieldSet.getDefaultInstance());
        return builder;
      }

      @Override
      public void write(Builder builder, DataOutputStream out) throws IOException {
        Message message = builder.build();
        out.writeInt(message.getSerializedSize());
        message.writeTo(out);
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

  /*
   * Ensures that only a single instance is created per builder class and shared among all mutators
   * that need it. This ensures that arbitrarily nested recursive structures such as a Protobuf
   * message type that contains itself as a message field are representable as fixed-size mutator
   * structures.
   *
   * Note: The resulting mutator structures may no longer form a tree: If A is a protobuf message
   * type with a message field B and B in turn has a message field of type A, then the mutators for
   * A and B will reference each other, forming a cycle.
   */
  private final HashMap<Class<? extends Builder>, SerializingMutator<Builder>> internedMutators =
      new HashMap<>();

  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    return asSubclassOrEmpty(type, Builder.class).map(builderClass -> {
      if (internedMutators.containsKey(builderClass)) {
        return internedMutators.get(builderClass);
      }
      Supplier<Builder> builderSupplier = makeBuilderSupplier(builderClass);
      // assemble inserts the instance of the newly created builder mutator into the
      // internedMutators map *before* recursively creating the mutators for its fields, which
      // ensures that the recursion is finite (bounded by the total number of distinct message types
      // that transitively occur as field types on the current message type).
      return assemble(mutator
          -> internedMutators.put(builderClass, mutator),
          builderSupplier, makeBuilderSerializer(builderSupplier),
          ()
              -> combine(
                  getDescriptor(builderClass)
                      .getFields()
                      .stream()
                      // Keep oneofs sorted by the first appearance of their fields in the
                      // .proto file.
                      .collect(groupingBy(
                          // groupingBy does not support null keys. We use getRealContainingOneof()
                          // instead of getContainingOneof() as the latter also reports oneofs for
                          // proto3 optional fields, which we handle separately.
                          fieldDescriptor
                          -> Optional.ofNullable(fieldDescriptor.getRealContainingOneof()),
                          LinkedHashMap::new, toList()))
                      .entrySet()
                      .stream()
                      .flatMap(entry
                          -> mutatorsForFields(
                              entry.getKey(), entry.getValue(), builderSupplier.get(), factory))
                      .toArray(InPlaceMutator[] ::new)));
    });
  }
}
