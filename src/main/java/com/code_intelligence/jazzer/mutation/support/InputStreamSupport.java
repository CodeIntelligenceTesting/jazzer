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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.lang.Math.max;
import static java.lang.Math.min;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

public final class InputStreamSupport {
  public static byte[] readAllBytes(InputStream stream) throws IOException {
    requireNonNull(stream);
    Queue<byte[]> buffers = new ArrayDeque<>();
    int arrayLength = 0;
    outer:
    while (true) {
      byte[] buffer = new byte[max(8192, stream.available())];
      buffers.add(buffer);
      int off = 0;
      while (off < buffer.length) {
        int bytesRead = stream.read(buffer, off, buffer.length - off);
        if (bytesRead == -1) {
          break outer;
        }
        off += bytesRead;
        arrayLength += bytesRead;
      }
    }

    byte[] result = new byte[arrayLength];
    int offset = 0;
    byte[] buffer;
    int remaining = arrayLength;
    while ((buffer = buffers.poll()) != null) {
      int toCopy = min(buffer.length, remaining);
      System.arraycopy(buffer, 0, result, offset, toCopy);
      remaining -= toCopy;
    }
    return result;
  }

  private static final InputStream infiniteZerosStream = new ExtendWithNullInputStream();

  /**
   * @return an infinite stream consisting of 0s
   */
  public static InputStream infiniteZeros() {
    return infiniteZerosStream;
  }

  /**
   * @return {@code stream} extended with 0s to an infinite stream
   */
  public static InputStream extendWithZeros(InputStream stream) {
    if (stream instanceof ExtendWithNullInputStream) {
      return stream;
    }
    return new ExtendWithNullInputStream(requireNonNull(stream));
  }

  public static final class ExtendWithNullInputStream extends InputStream {
    private static final InputStream ALWAYS_EOF = new ByteArrayInputStream(new byte[0]);
    private final InputStream stream;
    private boolean eof;

    private ExtendWithNullInputStream() {
      this.stream = ALWAYS_EOF;
      this.eof = true;
    }

    private ExtendWithNullInputStream(InputStream stream) {
      this.stream = stream;
      this.eof = false;
    }

    @Override
    public int read() throws IOException {
      if (eof) {
        return 0;
      }

      int res = stream.read();
      if (res != -1) {
        return res;
      } else {
        eof = true;
        return 0;
      }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (eof) {
        Arrays.fill(b, off, off + len, (byte) 0);
      } else {
        int bytesRead = stream.read(b, off, len);
        if (bytesRead < len) {
          eof = true;
          Arrays.fill(b, max(off, off + bytesRead), off + len, (byte) 0);
        }
      }
      return len;
    }

    @Override
    public int available() throws IOException {
      if (eof) {
        return Integer.MAX_VALUE;
      } else {
        return stream.available();
      }
    }

    @Override
    public void close() throws IOException {
      stream.close();
    }
  }

  /**
   * @return a stream with the first {@code bytes} bytes of {@code stream}
   */
  public static InputStream cap(InputStream stream, long bytes) {
    requireNonNull(stream);
    require(bytes >= 0, "bytes must be non-negative");
    return new CappedInputStream(stream, bytes);
  }

  private static final class CappedInputStream extends InputStream {
    private final InputStream stream;
    private long remaining;

    CappedInputStream(InputStream stream, long remaining) {
      this.stream = stream;
      this.remaining = remaining;
    }

    @Override
    public int read() throws IOException {
      if (remaining == 0) {
        return -1;
      }

      int res = stream.read();
      if (res != -1) {
        --remaining;
      }
      return res;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (remaining == 0) {
        return -1;
      }

      int res = stream.read(b, off, (int) min(len, remaining));
      if (res != -1) {
        remaining -= res;
      }
      return res;
    }

    @Override
    public int available() throws IOException {
      return (int) min(stream.available(), remaining);
    }

    @Override
    public void close() throws IOException {
      stream.close();
    }
  }

  private InputStreamSupport() {}
}
