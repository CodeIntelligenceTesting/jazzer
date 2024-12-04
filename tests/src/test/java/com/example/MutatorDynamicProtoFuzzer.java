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

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.google.protobuf.DescriptorProtos.DescriptorProto;
import com.google.protobuf.DescriptorProtos.FieldDescriptorProto;
import com.google.protobuf.DescriptorProtos.FieldDescriptorProto.Type;
import com.google.protobuf.DescriptorProtos.FileDescriptorProto;
import com.google.protobuf.Descriptors.DescriptorValidationException;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FileDescriptor;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.Message;

public class MutatorDynamicProtoFuzzer {
  public static void fuzzerTestOneInput(
      @NotNull @WithDefaultInstance("com.example.MutatorDynamicProtoFuzzer#getDefaultInstance")
          Message proto) {
    FieldDescriptor I32 = proto.getDescriptorForType().findFieldByName("i32");
    FieldDescriptor STR = proto.getDescriptorForType().findFieldByName("str");
    if (proto.getField(I32).equals(1234) && proto.getField(STR).equals("abcd")) {
      throw new FuzzerSecurityIssueMedium("Secret proto is found!");
    }
  }

  @SuppressWarnings("unused")
  private static DynamicMessage getDefaultInstance() {
    DescriptorProto myMessage =
        DescriptorProto.newBuilder()
            .setName("my_message")
            .addField(
                FieldDescriptorProto.newBuilder()
                    .setNumber(1)
                    .setName("i32")
                    .setType(Type.TYPE_INT32))
            .addField(
                FieldDescriptorProto.newBuilder()
                    .setNumber(2)
                    .setName("str")
                    .setType(Type.TYPE_STRING))
            .build();
    FileDescriptorProto file =
        FileDescriptorProto.newBuilder()
            .setName("my_protos.proto")
            .addMessageType(myMessage)
            .build();
    try {
      return DynamicMessage.getDefaultInstance(
          FileDescriptor.buildFrom(file, new FileDescriptor[0])
              .findMessageTypeByName("my_message"));
    } catch (DescriptorValidationException e) {
      throw new IllegalStateException(e);
    }
  }
}
