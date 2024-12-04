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

package com.code_intelligence.jazzer.mutation.api;

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithZeros;

import com.google.errorprone.annotations.CheckReturnValue;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Serializes and deserializes values of type {@code T>} to and from (in-memory or on disk) corpus
 * entries.
 *
 * <p>Binary representations must by default be self-delimiting. For variable-length types, the
 * {@link #readExclusive(InputStream)} and {@link #writeExclusive(Object, OutputStream)} methods can
 * optionally be overriden to implement more compact representations that align with existing binary
 * corpus entries. For example, a {@code Serializer<byte[]>} could implement these optional methods
 * to read and write the raw bytes without preceding length information whenever it is used in an
 * already delimited context.
 */
public interface Serializer<T> extends Detacher<T> {
  /**
   * Reads a {@code T} from an endless stream that is eventually 0.
   *
   * <p>Implementations
   *
   * <ul>
   *   <li>MUST not attempt to consume the entire stream;
   *   <li>MUST return a valid {@code T} and not throw for any (even garbage) stream;
   *   <li>SHOULD short-circuit the creation of nested structures upon reading null bytes.
   * </ul>
   *
   * @param in an endless stream that eventually only reads null bytes
   * @return a {@code T} constructed from the bytes read
   * @throws IOException declared, but must not be thrown by implementations unless methods called
   *     on {@code in} do
   */
  @CheckReturnValue
  T read(DataInputStream in) throws IOException;

  /**
   * Writes a {@code T} to a stream in such a way that an equal object can be recovered from the
   * written bytes via {@link #read(DataInputStream)}.
   *
   * <p>Since {@link #read(DataInputStream)} is called with an endless stream, the binary
   * representation MUST be self-delimiting. For example, when writing out a list, first write its
   * length.
   *
   * @param value the value to write
   * @param out the stream to write to
   * @throws IOException declared, but must not be thrown by implementations unless methods called
   *     on {@code out} do
   */
  void write(T value, DataOutputStream out) throws IOException;

  /**
   * Reads a {@code T} from a finite stream, potentially using a simpler representation than that
   * read by {@link #read(DataInputStream)}.
   *
   * <p>The default implementations call extends the stream with null bytes and then calls {@link
   * #read(DataInputStream)}.
   *
   * <p>Implementations
   *
   * <ul>
   *   <li>MUST return a valid {@code T} and not throw for any (even garbage) stream;
   *   <li>SHOULD short-circuit the creation of nested structures upon reading null bytes;
   *   <li>SHOULD naturally consume the entire stream.
   * </ul>
   *
   * @param in a finite stream
   * @return a {@code T} constructed from the bytes read
   * @throws IOException declared, but must not be thrown by implementations unless methods called
   *     on {@code in} do
   */
  @CheckReturnValue
  default T readExclusive(InputStream in) throws IOException {
    return read(new DataInputStream(extendWithZeros(in)));
  }

  /**
   * Writes a {@code T} to a stream in such a way that an equal object can be recovered from the
   * written bytes via {@link #readExclusive(InputStream)}.
   *
   * <p>The default implementations calls through to {@link #read(DataInputStream)} and should only
   * be overriden if {@link #readExclusive(InputStream)} is.
   *
   * <p>As opposed to {@link #read(DataInputStream)}, {@link #readExclusive(InputStream)} is called
   * with a finite stream. The binary representation of a {@code T} value thus does not have to be
   * self-delimiting, which can allow for simpler representations. For example, a {@code byte[]} can
   * be written to the stream without prepending its length.
   *
   * @param value the value to write
   * @param out the stream to write to
   * @throws IOException declared, but must not be thrown by implementations unless methods called
   *     on {@code out} do
   */
  default void writeExclusive(T value, OutputStream out) throws IOException {
    write(value, new DataOutputStream(out));
  }
}
