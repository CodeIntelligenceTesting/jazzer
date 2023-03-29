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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.check;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withTypeArguments;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.EnumValueDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;

final class TypeLibrary {
  private static final AnnotatedType RAW_LIST = new TypeHolder<@NotNull List>() {}.annotatedType();
  private static final AnnotatedType RAW_MAP = new TypeHolder<@NotNull Map>() {}.annotatedType();

  static <T extends Builder> AnnotatedType getTypeToMutate(
      FieldDescriptor field, T builder, Annotation[] messageFieldAnnotations) {
    if (field.isRequired()) {
      return getBaseType(field, builder, messageFieldAnnotations);
    } else if (field.isMapField()) {
      // Map fields are represented as repeated message fields, so this check has to come before the
      // one for regular repeated fields.
      //
      // Get a builder for the synthetic MapEntry message used to represent a single entry in the
      // repeated message field representation of a map field.
      Builder entryBuilder = builder.newBuilderForField(field);
      FieldDescriptor keyField = field.getMessageType().getFields().get(0);
      AnnotatedType keyType = getBaseType(keyField, entryBuilder, messageFieldAnnotations);
      FieldDescriptor valueField = field.getMessageType().getFields().get(1);
      AnnotatedType valueType = getBaseType(valueField, entryBuilder, messageFieldAnnotations);
      return withTypeArguments(RAW_MAP, keyType, valueType);
    } else if (field.isRepeated()) {
      return withTypeArguments(RAW_LIST, getBaseType(field, builder, messageFieldAnnotations));
    } else if (field.hasPresence()) {
      return getBaseTypeWithPresence(field, builder, messageFieldAnnotations);
    } else {
      return getBaseType(field, builder, messageFieldAnnotations);
    }
  }

  private static <T extends Builder> AnnotatedType getBaseType(
      FieldDescriptor field, T builder, Annotation[] messageFieldAnnotations) {
    return notNull(getBaseTypeWithPresence(field, builder, messageFieldAnnotations));
  }

  @SuppressWarnings("DuplicateBranchesInSwitch") /* False positives caused by TypeHolder */
  private static <T extends Builder> AnnotatedType getBaseTypeWithPresence(
      FieldDescriptor field, T builder, Annotation[] messageFieldAnnotations) {
    switch (field.getJavaType()) {
      case BOOLEAN:
        return new TypeHolder<Boolean>() {}.annotatedType();
      case MESSAGE:
        return withExtraAnnotations(
            asAnnotatedType(
                builder.newBuilderForField(field).getDefaultInstanceForType().getClass()),
            messageFieldAnnotations);
      case INT:
        return new TypeHolder<Integer>() {}.annotatedType();
      case LONG:
        return new TypeHolder<Long>() {}.annotatedType();
      case BYTE_STRING:
        return new TypeHolder<ByteString>() {}.annotatedType();
      case STRING:
        return new TypeHolder<String>() {}.annotatedType();
      case ENUM:
        return new TypeHolder<EnumValueDescriptor>() {}.annotatedType();
      case FLOAT:
        return new TypeHolder<Float>() {}.annotatedType();
      case DOUBLE:
        return new TypeHolder<Double>() {}.annotatedType();
      default:
        throw new IllegalStateException("Unexpected type: " + field.getType());
    }
  }

  private TypeLibrary() {}

  static Message getDefaultInstance(Class<? extends Message> messageClass) {
    Method getDefaultInstance;
    try {
      getDefaultInstance = messageClass.getMethod("getDefaultInstance");
      check(Modifier.isStatic(getDefaultInstance.getModifiers()));
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(
          format("Message class for builder type %s does not have a getDefaultInstance method",
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
}
