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
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import org.apache.commons.compress.compressors.z.ZCompressorInputStream;

public class ZlibFuzzer {
  private static final int MAX_DECOMPRESSED_BYTES = 1 << 20; // 1 MiB

  public static void fuzzerTestOneInput(byte[] data) {
    try {
      DecompressionResult jdkResult = decompressWithJdk(data);
      DecompressionResult commonsResult = decompressWithCommons(data);

      if (!jdkResult.success && !commonsResult.success) {
        return;
      }
      if (jdkResult.success != commonsResult.success) {
        throw new AssertionError(
            "Differential zlib parse: JDK="
                + jdkResult.description
                + " Commons="
                + commonsResult.description);
      }

      byte[] payload = jdkResult.data;
      if (!Arrays.equals(payload, commonsResult.data)) {
        throw new AssertionError("Zlib plaintext mismatch");
      }

      byte[] jdkCompressed = compressWithJdk(payload);
      verifyRoundTrip(payload, jdkCompressed);
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }

  private static void verifyRoundTrip(byte[] expected, byte[] compressed) throws IOException {
    DecompressionResult viaJdk = decompressWithJdk(compressed);
    DecompressionResult viaCommons = decompressWithCommons(compressed);
    if (!viaJdk.success || !viaCommons.success) {
      throw new AssertionError(
          "Failed to decode recompressed zlib stream: JDK="
              + viaJdk.description
              + " Commons="
              + viaCommons.description);
    }
    if (!Arrays.equals(expected, viaJdk.data) || !Arrays.equals(expected, viaCommons.data)) {
      throw new AssertionError("Recompressed zlib payload mismatch");
    }
  }

  private static DecompressionResult decompressWithJdk(byte[] data) {
    ByteArrayInputStream input = new ByteArrayInputStream(data);
    try (InflaterInputStream iis = new InflaterInputStream(input)) {
      byte[] payload = readBounded(iis);
      ensureFullyConsumed(input);
      return DecompressionResult.success(payload);
    } catch (IOException e) {
      return DecompressionResult.failure(e.getClass().getName());
    }
  }

  private static DecompressionResult decompressWithCommons(byte[] data) {
    ByteArrayInputStream input = new ByteArrayInputStream(data);
    try (ZCompressorInputStream zis = new ZCompressorInputStream(input)) {
      byte[] payload = readBounded(zis);
      ensureFullyConsumed(input);
      return DecompressionResult.success(payload);
    } catch (IOException e) {
      return DecompressionResult.failure(e.getClass().getName());
    }
  }

  private static byte[] compressWithJdk(byte[] data) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DeflaterOutputStream dos = new DeflaterOutputStream(baos)) {
      dos.write(data);
    }
    return baos.toByteArray();
  }

  private static byte[] readBounded(java.io.InputStream is) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int total = 0;
    int read;
    while ((read = is.read(buffer)) != -1) {
      total += read;
      if (total > MAX_DECOMPRESSED_BYTES) {
        throw new IOException("decompressed data too large");
      }
      baos.write(buffer, 0, read);
    }
    return baos.toByteArray();
  }

  private static void ensureFullyConsumed(ByteArrayInputStream inputStream) throws IOException {
    if (inputStream.available() != 0) {
      throw new IOException("trailing bytes after zlib payload: " + inputStream.available());
    }
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
