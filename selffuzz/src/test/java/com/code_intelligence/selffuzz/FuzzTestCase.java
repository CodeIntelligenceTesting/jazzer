/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.selffuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.proto.ProtoMutators;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.DescriptorProtos;
import com.google.protobuf.DescriptorProtos.DescriptorProto;
import com.google.protobuf.DescriptorProtos.FileDescriptorProto;
import com.google.protobuf.Descriptors;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.Descriptors.FileDescriptor;
import com.google.protobuf.Message;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class FuzzTestCase {
  @FuzzTest(maxDuration = "10m")
  void stringMutatorTest(byte[] data) {
    SerializingMutator<String> mutator =
        (SerializingMutator<String>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<String>() {}.annotatedType());

    try (DataInputStream stream = Helpers.infiniteByteStream(data)) {
      String out = mutator.read(stream);
    } catch (EOFException e) {
      // ignore end of file exceptions which can happen due to an invalid length in the input byte
      // array
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static String protoName;
  private static FileDescriptorProto file;

  // https://protobuf.dev/reference/protobuf/proto3-spec/#identifiers
  private static Pattern protoNamePattern = Pattern.compile("^[a-zA-Z][a-zA-Z._]$");

  @FuzzTest
  void dynamicMessageFuzzTest(@NotNull DescriptorProto messageType, byte @NotNull [] bytes) {
    System.out.printf("messageType: %s%n", messageType);
    if (messageType == null) {
      return;
    }

    /*
    protoName = messageType.getName();
    Matcher matcher = protoNamePattern.matcher(protoName);
    System.out.println(protoName);
    if (!matcher.find()) {
      return;
    }
     */
    file = FileDescriptorProto.newBuilder()
            .setName("my_protos.proto")
            .addMessageType(messageType)
            .build();

    try (DataInputStream stream = Helpers.infiniteByteStream(bytes)) {

      SerializingMutator<DynamicMessage> mutator =
              (SerializingMutator<DynamicMessage>) ProtoMutators.newFactory()
                      .createOrThrow(
                              new TypeHolder<@WithDefaultInstance("com.code_intelligence.selffuzz.FuzzTestCase#getDefaultInstance") DynamicMessage>() {}.annotatedType());
      DynamicMessage out = mutator.read(stream);
      System.out.println(protoName);
    } catch (IllegalArgumentException e) {
      // an invalid proto descriptor will throw a DescriptorValidationException below but by the time it gets here
      // it'll be an IllegalArgumentException
      return;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("unused")
  private static DynamicMessage getDefaultInstance() {
    try {
      return DynamicMessage.getDefaultInstance(
              FileDescriptor.buildFrom(file, new FileDescriptor[0])
                      .findMessageTypeByName(protoName));
    } catch (Descriptors.DescriptorValidationException e) {
      throw new IllegalStateException(e);
    }
  }
}
