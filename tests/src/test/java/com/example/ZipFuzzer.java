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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ZipFuzzer {
  private static final int MAX_ENTRIES = 16;
  private static final int MAX_ENTRY_BYTES = 1 << 17; // 128 KiB per entry

  public static void fuzzerTestOneInput(byte[] data) throws IOException {
    try {
      List<EntryData> parsedEntries =
          extractEntries(new ZipInputStream(new ByteArrayInputStream(data)));
      if (parsedEntries.isEmpty()) {
        return;
      }

      byte[] rezipped = rezipEntries(parsedEntries);
      List<EntryData> roundTripEntries =
          extractEntries(new ZipInputStream(new ByteArrayInputStream(rezipped)));
      assertEquivalent(parsedEntries, roundTripEntries);
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }

  private static List<EntryData> extractEntries(ZipInputStream zis) throws IOException {
    try (ZipInputStream zipInputStream = zis) {
      List<EntryData> entries = new ArrayList<>();
      ZipEntry entry;
      int index = 0;
      while (index < MAX_ENTRIES && (entry = zipInputStream.getNextEntry()) != null) {
        entries.add(readEntry(zipInputStream, entry, index));
        zipInputStream.closeEntry();
        index++;
      }
      return entries;
    }
  }

  private static EntryData readEntry(ZipInputStream zis, ZipEntry entry, int index)
      throws IOException {
    String name = entry.getName();
    if (name == null || name.isEmpty()) {
      name = "entry-" + index;
    }

    ByteArrayOutputStream entryData = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    int stored = 0;
    int read;
    while ((read = zis.read(buffer)) != -1) {
      if (stored < MAX_ENTRY_BYTES) {
        int toWrite = Math.min(MAX_ENTRY_BYTES - stored, read);
        entryData.write(buffer, 0, toWrite);
        stored += toWrite;
      }
    }
    return new EntryData(name, entryData.toByteArray());
  }

  private static byte[] rezipEntries(List<EntryData> entries) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      for (EntryData entry : entries) {
        ZipEntry newEntry = new ZipEntry(entry.name);
        zos.putNextEntry(newEntry);
        zos.write(entry.data);
        zos.closeEntry();
      }
    }
    return baos.toByteArray();
  }

  private static void assertEquivalent(List<EntryData> original, List<EntryData> roundTrip) {
    if (original.size() != roundTrip.size()) {
      throw new AssertionError(
          "Round-trip entry count mismatch: " + original.size() + " vs " + roundTrip.size());
    }

    for (int i = 0; i < original.size(); i++) {
      EntryData expected = original.get(i);
      EntryData actual = roundTrip.get(i);
      if (!expected.name.equals(actual.name)) {
        throw new AssertionError(
            String.format("Entry %d name mismatch: %s vs %s", i, expected.name, actual.name));
      }
      if (!Arrays.equals(expected.data, actual.data)) {
        throw new AssertionError("Entry " + expected.name + " payload mismatch");
      }
    }
  }

  private static final class EntryData {
    final String name;
    final byte[] data;

    EntryData(String name, byte[] data) {
      this.name = name;
      this.data = data;
    }
  }
}
