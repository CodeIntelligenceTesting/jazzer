/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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

public class ExperimentalMutatorDynamicProtoFuzzer {
  public static void fuzzerTestOneInput(
      @NotNull
          @WithDefaultInstance(
              "com.example.ExperimentalMutatorDynamicProtoFuzzer#getDefaultInstance")
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
