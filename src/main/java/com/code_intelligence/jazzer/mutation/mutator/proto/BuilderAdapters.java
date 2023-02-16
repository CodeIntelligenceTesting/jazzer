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

import static java.lang.String.format;

import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message.Builder;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;

final class BuilderAdapters {
  static <T extends Builder, U> List<U> makeMutableRepeatedFieldView(
      T builder, FieldDescriptor field) {
    return new AbstractList<U>() {
      @Override
      public U get(int index) {
        return (U) builder.getRepeatedField(field, index);
      }

      @Override
      public int size() {
        return builder.getRepeatedFieldCount(field);
      }

      @Override
      public boolean add(U u) {
        builder.addRepeatedField(field, u);
        return true;
      }

      @Override
      public U set(int index, U element) {
        U previous = get(index);
        builder.setRepeatedField(field, index, element);
        return previous;
      }

      @Override
      public U remove(int index) {
        int size = size();
        if (index < 0 || index >= size) {
          throw new IndexOutOfBoundsException(
              format("index %d out of bounds for size %d", index, size));
        }

        ArrayList<U> temp = new ArrayList<>(this);
        builder.clearField(field);

        U removed = temp.get(index);
        for (int i = 0; i < size; i++) {
          if (i != index) {
            builder.addRepeatedField(field, temp.get(i));
          }
        }

        return removed;
      }
    };
  }

  static <T extends Builder> List<Builder> makeMutableRepeatedMessageFieldView(
      T builder, FieldDescriptor field) {
    return new AbstractList<Builder>() {
      @Override
      public Builder get(int index) {
        return builder.getRepeatedFieldBuilder(field, index);
      }

      @Override
      public int size() {
        return builder.getRepeatedFieldCount(field);
      }

      @Override
      public boolean add(Builder fieldBuilder) {
        builder.addRepeatedField(field, fieldBuilder.build());
        return true;
      }

      @Override
      public Builder set(int index, Builder fieldBuilder) {
        Builder previous = get(index);
        builder.setRepeatedField(field, index, fieldBuilder.build());
        return previous;
      }

      @Override
      public Builder remove(int index) {
        int size = size();
        if (index < 0 || index >= size) {
          throw new IndexOutOfBoundsException(
              format("index %d out of bounds for size %d", index, size));
        }

        ArrayList<Builder> temp = new ArrayList<>(this);
        builder.clearField(field);

        Builder removed = temp.get(index);
        for (int i = 0; i < size; i++) {
          if (i != index) {
            builder.addRepeatedField(field, temp.get(i).build());
          }
        }

        return removed;
      }
    };
  }

  static <T extends Builder, U> U getPresentFieldOrNull(T builder, FieldDescriptor field) {
    if (builder.hasField(field)) {
      return (U) builder.getField(field);
    } else {
      return null;
    }
  }

  static <T extends Builder, U> void setFieldWithPresence(
      T builder, FieldDescriptor field, U value) {
    if (value == null) {
      builder.clearField(field);
    } else {
      builder.setField(field, value);
    }
  }

  static <T extends Builder> Builder getMessageField(T builder, FieldDescriptor field) {
    if (builder.hasField(field)) {
      return builder.getFieldBuilder(field);
    } else {
      return null;
    }
  }

  static <T extends Builder> void setMessageField(
      T builder, FieldDescriptor field, Builder fieldBuilder) {
    if (fieldBuilder == null) {
      builder.clearField(field);
    } else {
      builder.setField(field, fieldBuilder.build());
    }
  }

  private BuilderAdapters() {}
}
