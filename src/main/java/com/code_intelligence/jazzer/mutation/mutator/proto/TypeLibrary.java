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

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withTypeArguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.Type;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.List;

final class TypeLibrary {
  private static final Annotation NOT_NULL =
      new TypeHolder<@NotNull String>() {}.annotatedType().getAnnotation(NotNull.class);
  private static final AnnotatedType RAW_LIST = new TypeHolder<@NotNull List>() {}.annotatedType();

  static AnnotatedType getTypeToMutate(FieldDescriptor field) {
    if (field.isMapField()) {
      throw new UnsupportedOperationException("Map fields haven't been implemented yet");
    }
    if (field.isRequired()) {
      throw new UnsupportedOperationException("Required fields haven't been implemented yet");
    }

    if (field.isRepeated()) {
      return withTypeArguments(RAW_LIST, getBaseType(field.getType()));
    } else if (field.hasPresence()) {
      return getBaseTypeWithPresence(field.getType());
    } else {
      return getBaseType(field.getType());
    }
  }

  private static AnnotatedType getBaseType(Type type) {
    return withExtraAnnotations(getBaseTypeWithPresence(type), NOT_NULL);
  }

  private static AnnotatedType getBaseTypeWithPresence(Type type) {
    switch (type) {
      case BOOL:
        return new TypeHolder<Boolean>() {}.annotatedType();
      case BYTES:
      case DOUBLE:
      case ENUM:
      case FIXED32:
      case FIXED64:
      case FLOAT:
      case GROUP:
      case INT32:
      case INT64:
      case MESSAGE:
      case SFIXED32:
      case SFIXED64:
      case SINT32:
      case SINT64:
      case STRING:
      case UINT32:
      case UINT64:
        throw new UnsupportedOperationException(type + " has not been implemented");
      default:
        throw new IllegalStateException("Unexpected type: " + type);
    }
  }

  private TypeLibrary() {}
}
