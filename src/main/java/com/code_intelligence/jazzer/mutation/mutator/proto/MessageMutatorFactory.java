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

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.cap;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;

import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import com.google.protobuf.Parser;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.function.Supplier;

public final class MessageMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    if (!findFirstParentIfClass(type, Message.class).isPresent()) {
      return Optional.empty();
    }
    Class<?> messageClass = (Class<?>) type.getType();
    if (messageClass == Message.class) {
      // We can only mutate concrete message types.
      return Optional.empty();
    }

    Parser<? extends Message> parser;
    try {
      parser = (Parser<? extends Message>) messageClass.getMethod("parser").invoke(null);
    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
      throw new IllegalStateException(e);
    }

    Class<Builder> builderClass;
    Supplier<Builder> makeBuilder;
    try {
      Method newBuilder = messageClass.getMethod("newBuilder");
      builderClass = (Class<Builder>) newBuilder.getReturnType();
      makeBuilder = () -> {
        try {
          return (Builder) newBuilder.invoke(null);
        } catch (IllegalAccessException | InvocationTargetException e) {
          throw new IllegalStateException(e);
        }
      };
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    }

    return new BuilderMutatorFactory()
        .tryCreate(builderClass, factory)
        .map(builderMutator -> new MessageMutator(builderMutator, parser, makeBuilder));
  }

  private static final class MessageMutator implements SerializingMutator<Message> {
    private final InPlaceMutator<Builder> builderMutator;
    private final Parser<? extends Message> parser;
    private final Supplier<Builder> makeBuilder;

    MessageMutator(InPlaceMutator<Builder> builderMutator, Parser<? extends Message> parser,
        Supplier<Builder> makeBuilder) {
      this.builderMutator = builderMutator;
      this.parser = parser;
      this.makeBuilder = makeBuilder;
    }

    @Override
    public Message read(DataInputStream in) throws IOException {
      int length = in.readInt();
      return parser.parseFrom(cap(in, length));
    }

    @Override
    public Message readExclusive(InputStream in) throws IOException {
      return parser.parseFrom(in);
    }

    @Override
    public void write(Message value, DataOutputStream out) throws IOException {
      out.writeInt(value.getSerializedSize());
      value.writeTo(out);
    }

    @Override
    public void writeExclusive(Message value, OutputStream out) throws IOException {
      value.writeTo(out);
    }

    @Override
    public Message init(PseudoRandom prng) {
      Builder builder = makeBuilder.get();
      builderMutator.initInPlace(builder, prng);
      return builder.build();
    }

    @Override
    public Message mutate(Message value, PseudoRandom prng) {
      // TODO: Measure performance and use a WeakIdentityHashMap cache if toBuilder turns out to be
      //  a bottleneck.
      Builder builder = value.toBuilder();
      builderMutator.mutateInPlace(builder, prng);
      return builder.build();
    }

    @Override
    public Message detach(Message value) {
      // Protobuf messages are immutable.
      return value;
    }
  }
}
