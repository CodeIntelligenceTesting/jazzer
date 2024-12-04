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

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.withoutInit;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.check;
import static com.code_intelligence.jazzer.mutation.support.StreamSupport.entry;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.containedInDirectedCycle;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withTypeArguments;
import static java.lang.String.format;
import static java.util.Collections.unmodifiableMap;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toMap;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.EnumValueDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.JavaType;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

final class TypeLibrary {
  private static final AnnotatedType RAW_LIST = new TypeHolder<@NotNull List>() {}.annotatedType();
  private static final AnnotatedType RAW_MAP = new TypeHolder<@NotNull Map>() {}.annotatedType();
  private static final Map<JavaType, AnnotatedType> BASE_TYPE_WITH_PRESENCE =
      Stream.of(
              entry(JavaType.BOOLEAN, new TypeHolder<Boolean>() {}.annotatedType()),
              entry(JavaType.BYTE_STRING, new TypeHolder<ByteString>() {}.annotatedType()),
              entry(JavaType.DOUBLE, new TypeHolder<Double>() {}.annotatedType()),
              entry(JavaType.ENUM, new TypeHolder<EnumValueDescriptor>() {}.annotatedType()),
              entry(JavaType.FLOAT, new TypeHolder<Float>() {}.annotatedType()),
              entry(JavaType.INT, new TypeHolder<Integer>() {}.annotatedType()),
              entry(JavaType.LONG, new TypeHolder<Long>() {}.annotatedType()),
              entry(JavaType.MESSAGE, new TypeHolder<Message>() {}.annotatedType()),
              entry(JavaType.STRING, new TypeHolder<String>() {}.annotatedType()))
          .collect(
              collectingAndThen(
                  toMap(SimpleEntry::getKey, SimpleEntry::getValue),
                  map -> unmodifiableMap(new EnumMap<>(map))));

  private TypeLibrary() {}

  static <T extends Builder> AnnotatedType getTypeToMutate(FieldDescriptor field) {
    if (field.isRequired()) {
      return getBaseType(field);
    } else if (field.isMapField()) {
      // Map fields are represented as repeated message fields, so this check has to come before the
      // one for regular repeated fields.
      AnnotatedType keyType = getBaseType(field.getMessageType().getFields().get(0));
      AnnotatedType valueType = getBaseType(field.getMessageType().getFields().get(1));
      return withTypeArguments(RAW_MAP, keyType, valueType);
    } else if (field.isRepeated()) {
      return withTypeArguments(RAW_LIST, getBaseType(field));
    } else if (field.hasPresence()) {
      return BASE_TYPE_WITH_PRESENCE.get(field.getJavaType());
    } else {
      return getBaseType(field);
    }
  }

  private static <T extends Builder> AnnotatedType getBaseType(FieldDescriptor field) {
    return notNull(BASE_TYPE_WITH_PRESENCE.get(field.getJavaType()));
  }

  static <T> InPlaceMutator<T> withoutInitIfRecursive(
      InPlaceMutator<T> mutator, FieldDescriptor field) {
    if (field.isRequired() || !isRecursiveField(field)) {
      return mutator;
    }
    return withoutInit(mutator);
  }

  static boolean isRecursiveField(FieldDescriptor field) {
    return containedInDirectedCycle(
        field,
        f -> {
          // For map fields, only the value can be a message.
          FieldDescriptor realField = f.isMapField() ? f.getMessageType().getFields().get(1) : f;
          if (realField.getJavaType() != JavaType.MESSAGE) {
            return Stream.empty();
          }
          return realField.getMessageType().getFields().stream();
        });
  }

  static Message getDefaultInstance(Class<? extends Message> messageClass) {
    Method getDefaultInstance;
    try {
      getDefaultInstance = messageClass.getMethod("getDefaultInstance");
      check(Modifier.isStatic(getDefaultInstance.getModifiers()));
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(
          format(
              "Message class for builder type %s does not have a getDefaultInstance method",
              messageClass.getName()),
          e);
    }
    try {
      return (Message) getDefaultInstance.invoke(null);
    } catch (IllegalAccessException | InvocationTargetException e) {
      throw new IllegalStateException(
          format(getDefaultInstance + " isn't accessible or threw an exception"), e);
    }
  }

  static Message getDefaultInstance(WithDefaultInstance withDefaultInstance) {
    String[] parts = withDefaultInstance.value().split("#");
    if (parts.length != 2) {
      throw new IllegalArgumentException(
          format(
              "Expected @WithDefaultInstance(\"%s\") to specify a fully-qualified method name"
                  + " (e.g. com.example.MyClass#getDefaultInstance)",
              withDefaultInstance.value()));
    }

    Class<?> clazz;
    try {
      clazz = Class.forName(parts[0]);
    } catch (ClassNotFoundException e) {
      throw new IllegalArgumentException(
          format(
              "Failed to find class '%s' specified by @WithDefaultInstance(\"%s\")",
              parts[0], withDefaultInstance.value()),
          e);
    }

    Method method;
    try {
      method = clazz.getDeclaredMethod(parts[1]);
      method.setAccessible(true);
    } catch (NoSuchMethodException e) {
      throw new IllegalArgumentException(
          format(
              "Failed to find method specified by @WithDefaultInstance(\"%s\")",
              withDefaultInstance.value()),
          e);
    }
    if (!Modifier.isStatic(method.getModifiers())) {
      throw new IllegalArgumentException(
          format(
              "Expected method specified by @WithDefaultInstance(\"%s\") to be static",
              withDefaultInstance.value()));
    }
    if (!Message.class.isAssignableFrom(method.getReturnType())) {
      throw new IllegalArgumentException(
          format(
              "Expected return type of method specified by @WithDefaultInstance(\"%s\") to be a"
                  + " subtype of %s, got %s",
              withDefaultInstance.value(),
              Message.class.getName(),
              method.getReturnType().getName()));
    }

    try {
      return (Message) method.invoke(null);
    } catch (IllegalAccessException | InvocationTargetException e) {
      throw new IllegalArgumentException(
          format(
              "Failed to execute method specified by @WithDefaultInstance(\"%s\")",
              withDefaultInstance.value()),
          e);
    }
  }

  static Optional<AnnotatedType> getBuilderType(Class<? extends Message> messageClass) {
    return Arrays.stream(messageClass.getDeclaredMethods())
        // Message#newBuilderForType() has return type Message.Builder, but overrides
        // MessageLite#newBuilderForType(), which has return type MessageLite.Builder. The Java
        // compiler adds a synthetic default method with return type MessageLite.Builder that we
        // don't want to pick up here.
        .filter(method -> !method.isSynthetic())
        .filter(method -> method.getName().equals("newBuilderForType"))
        .map(Method::getAnnotatedReturnType)
        .findFirst();
  }

  static AnnotatedType getMessageType(Class<? extends Message> messageClass) {
    return Arrays.stream(messageClass.getDeclaredMethods())
        .filter(method -> method.getName().equals("getDefaultInstance"))
        .map(Method::getAnnotatedReturnType)
        .findFirst()
        .get();
  }
}
