/*
 * Copyright 2025 Code Intelligence GmbH
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

package com.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateParameters;

public class DeflateFuzzer {
  private static final int MAX_DECOMPRESSED_BYTES = 1 << 20; // 1 MiB

  public static void fuzzerTestOneInput(byte[] data) {
    try {
      DecompressionResult jdkResult = decompressWithInflater(data);
      DecompressionResult commonsResult = decompressWithCommons(data);

      if (!jdkResult.success && !commonsResult.success) {
        return;
      }

      if (jdkResult.success != commonsResult.success) {
        throw new AssertionError(
            "Differential deflate parse: JDK="
                + jdkResult.description
                + " Commons="
                + commonsResult.description);
      }

      byte[] payload = jdkResult.data;
      if (!Arrays.equals(payload, commonsResult.data)) {
        throw new AssertionError("Deflate plaintext mismatch");
      }

      byte[] jdkCompressed = compressWithDeflater(payload);
      verifyRoundTrip(payload, jdkCompressed);

      byte[] commonsCompressed = compressWithCommons(payload);
      verifyRoundTrip(payload, commonsCompressed);
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }

  private static void verifyRoundTrip(byte[] expected, byte[] compressed) throws IOException {
    DecompressionResult viaInflater = decompressWithInflater(compressed);
    DecompressionResult viaCommons = decompressWithCommons(compressed);
    if (!viaInflater.success || !viaCommons.success) {
      throw new AssertionError(
          "Failed to decode recompressed deflate stream: JDK="
              + viaInflater.description
              + " Commons="
              + viaCommons.description);
    }
    if (!Arrays.equals(expected, viaInflater.data) || !Arrays.equals(expected, viaCommons.data)) {
      throw new AssertionError("Recompressed deflate payload mismatch");
    }
  }

  private static DecompressionResult decompressWithInflater(byte[] data) {
    Inflater inflater = new Inflater(true);
    inflater.setInput(data);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int total = 0;
    try {
      while (!inflater.finished() && !inflater.needsInput()) {
        int count = inflater.inflate(buffer);
        if (count == 0 && inflater.needsDictionary()) {
          return DecompressionResult.failure("dictionary-needed");
        }
        total += count;
        if (total > MAX_DECOMPRESSED_BYTES) {
          return DecompressionResult.failure("too-large");
        }
        baos.write(buffer, 0, count);
      }
      if (!inflater.finished()) {
        return DecompressionResult.failure("not-finished");
      }
      if (inflater.getRemaining() != 0) {
        return DecompressionResult.failure("trailing-bytes");
      }
      return DecompressionResult.success(baos.toByteArray());
    } catch (DataFormatException e) {
      return DecompressionResult.failure(e.getClass().getName());
    } finally {
      inflater.end();
    }
  }

  private static DecompressionResult decompressWithCommons(byte[] data) {
    ByteArrayInputStream input = new ByteArrayInputStream(data);
    DeflateParameters params = new DeflateParameters();
    params.setWithZlibHeader(false);
    try (DeflateCompressorInputStream cis = new DeflateCompressorInputStream(input, params)) {
      byte[] payload = cis.readAllBytes();
      if (payload.length > MAX_DECOMPRESSED_BYTES) {
        return DecompressionResult.failure("too-large");
      }
      if (input.available() != 0) {
        return DecompressionResult.failure("trailing-bytes");
      }
      return DecompressionResult.success(payload);
    } catch (IOException | IllegalArgumentException e) {
      return DecompressionResult.failure(e.getClass().getName());
    }
  }

  private static byte[] compressWithDeflater(byte[] data) throws IOException {
    Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater, true);
    dos.write(data);
    dos.finish();
    return baos.toByteArray();
  }

  private static byte[] compressWithCommons(byte[] data) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DeflateCompressorOutputStream cos = new DeflateCompressorOutputStream(baos)) {
      cos.write(data);
    }
    return baos.toByteArray();
  }

  private static final class DecompressionResult {
    final boolean success;
    final byte[] data;
    final String description;

    private DecompressionResult(boolean success, byte[] data, String description) {
      this.success = success;
      this.data = data;
      this.description = description;
    }

    static DecompressionResult success(byte[] data) {
      return new DecompressionResult(true, data, "OK");
    }

    static DecompressionResult failure(String description) {
      return new DecompressionResult(false, null, description);
    }
  }
}
