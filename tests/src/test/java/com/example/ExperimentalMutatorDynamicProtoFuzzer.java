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

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.proto.DescriptorSource;
import com.google.protobuf.DescriptorProtos.DescriptorProto;
import com.google.protobuf.DescriptorProtos.FieldDescriptorProto;
import com.google.protobuf.DescriptorProtos.FieldDescriptorProto.Type;
import com.google.protobuf.DescriptorProtos.FileDescriptorProto;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.DescriptorValidationException;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FileDescriptor;
import com.google.protobuf.DynamicMessage;

public class ExperimentalMutatorDynamicProtoFuzzer {
  private static final Descriptor DESCRIPTOR = makeDescriptor();
  private static final FieldDescriptor I32 = DESCRIPTOR.findFieldByName("i32");
  private static final FieldDescriptor STR = DESCRIPTOR.findFieldByName("str");

  public static void fuzzerTestOneInput(@NotNull @DescriptorSource(
      "com.example.ExperimentalMutatorDynamicProtoFuzzer#DESCRIPTOR") DynamicMessage proto) {
    if (proto.getField(I32).equals(1234) && proto.getField(STR).equals("abcd")) {
      throw new FuzzerSecurityIssueMedium("Secret proto is found!");
    }
  }

  private static Descriptor makeDescriptor() {
    DescriptorProto myMessage =
        DescriptorProto.newBuilder()
            .setName("my_message")
            .addField(FieldDescriptorProto.newBuilder().setNumber(1).setName("i32").setType(
                Type.TYPE_INT32))
            .addField(FieldDescriptorProto.newBuilder().setNumber(2).setName("str").setType(
                Type.TYPE_STRING))
            .build();
    FileDescriptorProto file = FileDescriptorProto.newBuilder()
                                   .setName("my_protos.proto")
                                   .addMessageType(myMessage)
                                   .build();
    try {
      return FileDescriptor.buildFrom(file, new FileDescriptor[0])
          .findMessageTypeByName("my_message");
    } catch (DescriptorValidationException e) {
      throw new IllegalStateException(e);
    }
  }
}
