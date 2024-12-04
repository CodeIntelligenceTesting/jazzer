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

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.assemble;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.combine;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.fixedValue;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateIndices;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProperty;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateSumInPlace;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateViaView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.getMapField;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.getPresentFieldOrNull;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.makeMutableRepeatedFieldView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.setFieldWithPresence;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.setMapField;
import static com.code_intelligence.jazzer.mutation.mutator.proto.TypeLibrary.getDefaultInstance;
import static com.code_intelligence.jazzer.mutation.mutator.proto.TypeLibrary.getMessageType;
import static com.code_intelligence.jazzer.mutation.mutator.proto.TypeLibrary.withoutInitIfRecursive;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.cap;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asSubclassOrEmpty;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.function.UnaryOperator.identity;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import com.code_intelligence.jazzer.mutation.annotation.proto.AnySource;
import com.code_intelligence.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import com.google.protobuf.Any;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.EnumDescriptor;
import com.google.protobuf.Descriptors.EnumValueDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.JavaType;
import com.google.protobuf.Descriptors.OneofDescriptor;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import com.google.protobuf.UnknownFieldSet;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class BuilderMutatorFactory implements MutatorFactory {
  private <T extends Builder, U> InPlaceMutator<T> mutatorForField(
      AnnotatedType initialType,
      FieldDescriptor field,
      Annotation[] annotations,
      ExtendedMutatorFactory factory) {
    factory = withDescriptorDependentMutatorFactoryIfNeeded(factory, field, annotations);
    AnnotatedType typeToMutate = TypeLibrary.getTypeToMutate(field);
    requireNonNull(typeToMutate, () -> "Java class not specified for " + field);

    // Propagate constraints from the field to the type to mutate.
    typeToMutate = propagatePropertyConstraints(initialType, typeToMutate);

    InPlaceMutator<T> mutator;
    if (field.isMapField()) {
      SerializingInPlaceMutator<Map> underlyingMutator =
          (SerializingInPlaceMutator<Map>) factory.createInPlaceOrThrow(typeToMutate);
      mutator =
          mutateProperty(
              builder -> getMapField(builder, field),
              underlyingMutator,
              (builder, value) -> setMapField(builder, field, value));
    } else if (field.isRepeated()) {
      SerializingInPlaceMutator<List<U>> underlyingMutator =
          (SerializingInPlaceMutator<List<U>>) factory.createInPlaceOrThrow(typeToMutate);
      mutator =
          mutateViaView(builder -> makeMutableRepeatedFieldView(builder, field), underlyingMutator);
    } else if (field.hasPresence()) {
      SerializingMutator<U> underlyingMutator =
          (SerializingMutator<U>) factory.createOrThrow(typeToMutate);
      mutator =
          mutateProperty(
              builder -> getPresentFieldOrNull(builder, field),
              underlyingMutator,
              (builder, value) -> setFieldWithPresence(builder, field, value));
    } else {
      SerializingMutator<U> underlyingMutator =
          (SerializingMutator<U>) factory.createOrThrow(typeToMutate);
      mutator =
          mutateProperty(
              builder -> (U) builder.getField(field),
              underlyingMutator,
              (builder, value) -> builder.setField(field, value));
    }

    // If recursive message fields (i.e. those that have themselves as transitive subfields) are
    // initialized eagerly, they tend to nest very deeply, which easily results in stack overflows.
    // We guard against that by making their init a no-op and instead initialize them layer by layer
    // in mutations.
    return withoutInitIfRecursive(mutator, field);
  }

  private ExtendedMutatorFactory withDescriptorDependentMutatorFactoryIfNeeded(
      ExtendedMutatorFactory originalFactory, FieldDescriptor field, Annotation[] annotations) {
    if (field.getJavaType() == JavaType.ENUM) {
      // Proto enum fields are special as their type (EnumValueDescriptor) does not encode their
      // domain - we need the actual EnumDescriptor instance.
      return ChainedMutatorFactory.of(
          originalFactory.getCache(),
          Stream.of(
              originalFactory,
              (type, factory) ->
                  asSubclassOrEmpty(type, EnumValueDescriptor.class)
                      .map(
                          unused -> {
                            EnumDescriptor enumType = field.getEnumType();
                            List<EnumValueDescriptor> values = enumType.getValues();
                            String name = enumType.getName();
                            if (values.size() == 1) {
                              // While we generally prefer to error out instead of creating a
                              // mutator that can't actually mutate its domain, we can't do that for
                              // proto enum fields as the user creating the fuzz test may not be in
                              // a position to modify the existing proto definition.
                              return fixedValue(values.get(0));
                            } else {
                              return mutateThenMapToImmutable(
                                  mutateIndices(values.size()),
                                  values::get,
                                  EnumValueDescriptor::getIndex,
                                  unused2 -> "Enum<" + name + ">");
                            }
                          })));
    } else if (field.getJavaType() == JavaType.MESSAGE) {
      Descriptor messageDescriptor;
      if (field.isMapField()) {
        // Map fields are represented as messages, but we mutate them as actual Java Maps. In case
        // the values of the proto map are themselves messages, we need to mutate their type.
        FieldDescriptor valueField = field.getMessageType().getFields().get(1);
        if (valueField.getJavaType() != JavaType.MESSAGE) {
          return originalFactory;
        }
        messageDescriptor = valueField.getMessageType();
      } else {
        messageDescriptor = field.getMessageType();
      }
      return ChainedMutatorFactory.of(
          originalFactory.getCache(),
          Stream.of(
              originalFactory,
              (type, factory) ->
                  asSubclassOrEmpty(type, Message.Builder.class)
                      .flatMap(
                          clazz -> {
                            // BuilderMutatorFactory only handles concrete subclasses of
                            // Message.Builder
                            // and requests Message.Builder itself for message fields, which we
                            // handle
                            // here.
                            if (clazz != Message.Builder.class) {
                              return Optional.empty();
                            }
                            // It is important that we use originalFactory here instead of factory:
                            // factory has this field-specific message mutator appended, but this
                            // mutator should only be used for this particular field and not any
                            // message
                            // subfields.
                            return Optional.of(
                                makeBuilderMutator(
                                    type,
                                    originalFactory,
                                    DynamicMessage.getDefaultInstance(messageDescriptor),
                                    annotations));
                          })));
    } else {
      return originalFactory;
    }
  }

  private <T extends Builder> Stream<InPlaceMutator<T>> mutatorsForFields(
      AnnotatedType initialType,
      Optional<OneofDescriptor> oneofField,
      List<FieldDescriptor> fields,
      Annotation[] annotations,
      ExtendedMutatorFactory factory) {
    if (oneofField.isPresent()) {
      // oneof fields are mutated as one as mutating them independently would cause the mutator to
      // erratically switch between the different states. The individual fields are kept in the
      // order in which they are defined in the .proto file.
      OneofDescriptor oneofDescriptor = oneofField.get();

      IdentityHashMap<FieldDescriptor, Integer> indexInOneof =
          new IdentityHashMap<>(oneofDescriptor.getFieldCount());
      for (int i = 0; i < oneofDescriptor.getFieldCount(); i++) {
        indexInOneof.put(oneofDescriptor.getField(i), i);
      }

      return Stream.of(
          mutateSumInPlace(
              (T builder) -> {
                FieldDescriptor setField = builder.getOneofFieldDescriptor(oneofDescriptor);
                if (setField == null) {
                  return -1;
                } else {
                  return indexInOneof.get(setField);
                }
              },
              // Mutating to the unset (-1) state is handled by the individual field mutators, which
              // are created nullable as oneof fields report that they track presence.
              fields.stream()
                  .map(field -> mutatorForField(initialType, field, annotations, factory))
                  .toArray(InPlaceMutator[]::new)));
    } else {
      // All non-oneof fields are mutated independently, using the order in which they are declared
      // in the .proto file (which may not coincide with the order by field number).
      return fields.stream()
          .map(field -> mutatorForField(initialType, field, annotations, factory));
    }
  }

  private static <M extends Message, B extends Builder> Serializer<B> makeBuilderSerializer(
      M defaultInstance) {
    return new Serializer<B>() {
      @Override
      public B read(DataInputStream in) throws IOException {
        int length = Math.max(in.readInt(), 0);
        return (B) parseLeniently(cap(in, length));
      }

      @Override
      public B readExclusive(InputStream in) throws IOException {
        return (B) parseLeniently(in);
      }

      private Builder parseLeniently(InputStream in) throws IOException {
        Builder builder = defaultInstance.toBuilder();
        try {
          builder.mergeFrom(in);
        } catch (InvalidProtocolBufferException ignored) {
          // builder has been partially modified with what could be decoded before the parser error.
        }
        // We never want the fuzz test to see unknown fields and our mutations should never produce
        // them.
        builder.setUnknownFields(UnknownFieldSet.getDefaultInstance());
        // Required fields may not have been set at this point. We set them to default values to
        // prevent an exception when built.
        forceInitialized(builder);
        return builder;
      }

      private void forceInitialized(Builder builder) {
        if (builder.isInitialized()) {
          return;
        }
        for (FieldDescriptor field : builder.getDescriptorForType().getFields()) {
          if (!field.isRequired()) {
            continue;
          }
          if (field.getJavaType() == JavaType.MESSAGE) {
            forceInitialized(builder.getFieldBuilder(field));
          } else if (!builder.hasField(field)) {
            builder.setField(field, field.getDefaultValue());
          }
        }
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
      public B detach(Builder builder) {
        return (B) builder.build().toBuilder();
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
  private final HashMap<CacheKey, SerializingMutator<? extends Builder>> internedMutators =
      new HashMap<>();

  private SerializingMutator<Any.Builder> mutatorForAny(
      AnySource anySource, ExtendedMutatorFactory factory) {
    Map<String, Integer> typeUrlToIndex =
        IntStream.range(0, anySource.value().length)
            .boxed()
            .collect(toMap(i -> getTypeUrl(getDefaultInstance(anySource.value()[i])), identity()));

    return assemble(
        mutator -> internedMutators.put(new CacheKey(Any.getDescriptor(), anySource), mutator),
        Any.getDefaultInstance()::toBuilder,
        makeBuilderSerializer(Any.getDefaultInstance()),
        () ->
            mutateSumInPlace(
                // Corpus entries may contain Anys with arbitrary (and even invalid) messages, so we
                // fall back to mutating the first message type if the type isn't recognized.
                (Any.Builder builder) -> typeUrlToIndex.getOrDefault(builder.getTypeUrl(), 0),
                stream(anySource.value())
                    .map(
                        messageClass -> {
                          SerializingMutator<Message> messageMutator =
                              (SerializingMutator<Message>)
                                  factory.createOrThrow(
                                      notNull(
                                          withExtraAnnotations(
                                              getMessageType(messageClass), anySource)));
                          return mutateProperty(
                              (Any.Builder anyBuilder) -> {
                                try {
                                  return anyBuilder.build().unpack(messageClass);
                                } catch (InvalidProtocolBufferException e) {
                                  // This can only happen if the corpus contains an invalid Any.
                                  return getDefaultInstance(messageClass);
                                }
                              },
                              messageMutator,
                              (Any.Builder any, Message message) -> {
                                any.setTypeUrl(getTypeUrl(message));
                                any.setValue(message.toByteString());
                              });
                        })
                    .toArray(InPlaceMutator[]::new)));
  }

  private static String getTypeUrl(Message message) {
    // We only support the default "type.googleapis.com" prefix.
    // https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/any.proto#L94
    return "type.googleapis.com/" + message.getDescriptorForType().getFullName();
  }

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    return asSubclassOrEmpty(type, Message.Builder.class)
        .flatMap(
            builderClass -> {
              Message defaultInstance;
              WithDefaultInstance withDefaultInstance =
                  type.getAnnotation(WithDefaultInstance.class);
              if (withDefaultInstance != null) {
                defaultInstance = getDefaultInstance(withDefaultInstance);
              } else if (builderClass == DynamicMessage.Builder.class) {
                throw new IllegalArgumentException(
                    "To mutate a dynamic message, add a @WithDefaultInstance annotation specifying"
                        + " the fully qualified method name of a static method returning a default"
                        + " instance");
              } else if (builderClass == Message.Builder.class) {
                // Handled by a custom mutator factory for message fields that is created in
                // withDescriptorDependentMutatorFactoryIfNeeded. Without @WithDefaultInstance,
                // BuilderMutatorFactory only handles proper subclasses, which correspond to
                // generated message types.
                return Optional.empty();
              } else {
                defaultInstance =
                    getDefaultInstance((Class<? extends Message>) builderClass.getEnclosingClass());
              }

              return Optional.of(
                  makeBuilderMutator(
                      type, factory, defaultInstance, type.getDeclaredAnnotations()));
            });
  }

  private SerializingMutator<?> makeBuilderMutator(
      AnnotatedType initialType,
      ExtendedMutatorFactory factory,
      Message defaultInstance,
      Annotation[] annotations) {
    AnySource anySource =
        (AnySource)
            stream(annotations)
                .filter(annotation -> annotation.annotationType() == AnySource.class)
                .findFirst()
                .orElse(null);
    Preconditions.require(
        anySource == null || anySource.value().length > 0,
        "@AnySource must list a non-empty list of classes");
    Descriptor descriptor = defaultInstance.getDescriptorForType();

    CacheKey cacheKey = new CacheKey(descriptor, anySource);
    if (internedMutators.containsKey(cacheKey)) {
      return internedMutators.get(cacheKey);
    }

    // If there is no @AnySource, mutate the Any.Builder fields just like a regular message.
    // TODO: Determine whether we should show a warning in this case.
    if (descriptor.equals(Any.getDescriptor()) && anySource != null) {
      return mutatorForAny(anySource, factory);
    }

    // assemble inserts the instance of the newly created builder mutator into the
    // internedMutators map *before* recursively creating the mutators for its fields, which
    // ensures that the recursion is finite (bounded by the total number of distinct message types
    // that transitively occur as field types on the current message type).
    return assemble(
        mutator -> internedMutators.put(cacheKey, mutator),
        defaultInstance::toBuilder,
        makeBuilderSerializer(defaultInstance),
        () ->
            combine(
                descriptor.getFields().stream()
                    // Keep oneofs sorted by the first appearance of their fields in the
                    // .proto file.
                    .collect(
                        groupingBy(
                            // groupingBy does not support null keys. We use
                            // getRealContainingOneof()
                            // instead of getContainingOneof() as the latter also reports oneofs for
                            // proto3 optional fields, which we handle separately.
                            fieldDescriptor ->
                                Optional.ofNullable(fieldDescriptor.getRealContainingOneof()),
                            LinkedHashMap::new,
                            toList()))
                    .entrySet()
                    .stream()
                    .flatMap(
                        entry ->
                            mutatorsForFields(
                                initialType,
                                entry.getKey(),
                                entry.getValue(),
                                anySource == null
                                    ? new Annotation[0]
                                    : new Annotation[] {anySource},
                                factory))
                    .toArray(InPlaceMutator[]::new)));
  }

  private static final class CacheKey {
    private final Descriptor descriptor;
    private final AnySource anySource;

    private CacheKey(Descriptor descriptor, AnySource anySource) {
      this.descriptor = descriptor;
      this.anySource = anySource;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      CacheKey cacheKey = (CacheKey) o;
      return descriptor == cacheKey.descriptor && Objects.equals(anySource, cacheKey.anySource);
    }

    @Override
    public int hashCode() {
      return 31 * System.identityHashCode(descriptor) + Objects.hashCode(anySource);
    }
  }
}
