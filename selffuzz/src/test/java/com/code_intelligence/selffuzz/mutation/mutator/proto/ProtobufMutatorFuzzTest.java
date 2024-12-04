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

package com.code_intelligence.selffuzz.mutation.mutator.proto;

import static com.code_intelligence.selffuzz.Helpers.assertMutator;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.proto.WithDefaultInstance;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.DescriptorProtos.DescriptorProto;
import com.google.protobuf.DescriptorProtos.FileDescriptorProto;
import com.google.protobuf.Descriptors;
import com.google.protobuf.Descriptors.FileDescriptor;
import com.google.protobuf.DynamicMessage;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.regex.Pattern;

@SuppressWarnings("unchecked")
class ProtobufMutatorFuzzTest {
  private static String protoName;
  private static FileDescriptorProto file;

  // https://protobuf.dev/reference/protobuf/proto3-spec/#identifiers
  private static final Pattern protoNamePattern = Pattern.compile("^[a-zA-Z][a-zA-Z._]$");

  @SuppressWarnings({"unchecked", "unused"})
  @FuzzTest
  void protobufMutatorTest(long seed, @NotNull DescriptorProto messageType, byte @NotNull [] bytes)
      throws IOException {
    protoName = messageType.getName();
    // the name has to be valid to create the filedescriptor, other invalid names will be caught
    // when constructing the mutator
    if (!protoNamePattern.matcher(protoName).matches()) {
      return;
    }
    file =
        FileDescriptorProto.newBuilder()
            .setName("my_protos.proto")
            .addMessageType(messageType)
            .build();

    SerializingMutator<DynamicMessage> mutator;
    try {
      mutator =
          (SerializingMutator<DynamicMessage>)
              Mutators.newFactory()
                  .createOrThrow(
                      new TypeHolder<
                          @WithDefaultInstance(
                              "com.code_intelligence.selffuzz.mutation.mutator.proto.ProtobufMutatorFuzzTest#getDefaultInstance")
                          DynamicMessage>() {}.annotatedType());
    } catch (IllegalArgumentException e) {
      // an invalid proto descriptor will throw a DescriptorValidationException below but by the
      // time it gets here it'll be wrapped in a couple layers of other exceptions. We peel it apart
      // to make sure we only ignore DescriptorValidationExceptions and throw the error if it's
      // anything else
      if (e.getCause() instanceof InvocationTargetException) {
        InvocationTargetException invocationException = (InvocationTargetException) e.getCause();
        if (invocationException.getTargetException().getCause()
            instanceof Descriptors.DescriptorValidationException) {
          return;
        }
      }
      throw e;
    }
    assertMutator(mutator, bytes, seed);
  }

  // this is actually used via reflection, see the TypeHolder above
  @SuppressWarnings("unused")
  private static DynamicMessage getDefaultInstance() {
    try {
      return DynamicMessage.getDefaultInstance(
          FileDescriptor.buildFrom(file, new FileDescriptor[0]).findMessageTypeByName(protoName));
    } catch (Descriptors.DescriptorValidationException e) {
      throw new IllegalStateException(e);
    }
  }
}
