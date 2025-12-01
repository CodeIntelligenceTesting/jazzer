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
import java.io.InputStream;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;

public class GzipFuzzer {
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
            "Differential gzip parse result: JDK="
                + jdkResult.description
                + " Commons="
                + commonsResult.description);
      }

      byte[] payload = jdkResult.data;
      if (!Arrays.equals(payload, commonsResult.data)) {
        throw new AssertionError("JDK and Commons gzip payload mismatch");
      }

      byte[] jdkCompressed = compressWithJdk(payload);
      verifyRoundTrip(payload, jdkCompressed);

      byte[] commonsCompressed = compressWithCommons(payload);
      verifyRoundTrip(payload, commonsCompressed);
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }

  private static void verifyRoundTrip(byte[] expected, byte[] compressed) throws IOException {
    DecompressionResult viaJdk = decompressWithJdk(compressed);
    DecompressionResult viaCommons = decompressWithCommons(compressed);
    if (!viaJdk.success || !viaCommons.success) {
      throw new AssertionError(
          "Failed to decompress recompressed data: JDK="
              + viaJdk.description
              + " Commons="
              + viaCommons.description);
    }
    if (!Arrays.equals(expected, viaJdk.data) || !Arrays.equals(expected, viaCommons.data)) {
      throw new AssertionError("Recompressed payload mismatch");
    }
  }

  private static DecompressionResult decompressWithJdk(byte[] data) {
    ByteArrayInputStream input = new ByteArrayInputStream(data);
    try (GZIPInputStream gis = new GZIPInputStream(input)) {
      byte[] payload = readBounded(gis);
      ensureFullyConsumed(input);
      return DecompressionResult.success(payload);
    } catch (IOException | IllegalArgumentException e) {
      return DecompressionResult.failure(e.getClass().getName());
    }
  }

  private static DecompressionResult decompressWithCommons(byte[] data) {
    ByteArrayInputStream input = new ByteArrayInputStream(data);
    try (GzipCompressorInputStream gis = new GzipCompressorInputStream(input, false)) {
      byte[] payload = readBounded(gis);
      ensureFullyConsumed(input);
      return DecompressionResult.success(payload);
    } catch (IOException | IllegalArgumentException e) {
      return DecompressionResult.failure(e.getClass().getName());
    }
  }

  private static byte[] compressWithJdk(byte[] data) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
      gos.write(data);
    }
    return baos.toByteArray();
  }

  private static byte[] compressWithCommons(byte[] data) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (GzipCompressorOutputStream gos = new GzipCompressorOutputStream(baos)) {
      gos.write(data);
    }
    return baos.toByteArray();
  }

  private static byte[] readBounded(InputStream inputStream) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int total = 0;
    int read;
    while ((read = inputStream.read(buffer)) != -1) {
      if (total + read > MAX_DECOMPRESSED_BYTES) {
        throw new IOException("decompressed data too large");
      }
      baos.write(buffer, 0, read);
      total += read;
    }
    return baos.toByteArray();
  }

  private static void ensureFullyConsumed(ByteArrayInputStream inputStream) throws IOException {
    if (inputStream.available() != 0) {
      throw new IOException("trailing bytes after gzip payload: " + inputStream.available());
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
