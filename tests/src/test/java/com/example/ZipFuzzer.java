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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;

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
      if (roundTripEntries.isEmpty()) {
        return;
      }

      assertEquivalent(parsedEntries, roundTripEntries);

      List<EntryData> commonsInputEntries = extractEntriesWithCommonsInput(rezipped);
      if (!commonsInputEntries.isEmpty()) {
        assertEquivalent(roundTripEntries, commonsInputEntries);
      }

      Path tempZip = writeTempZip(rezipped);
      try {
        List<EntryData> zipFileEntries = extractEntriesWithZipFile(tempZip);
        List<EntryData> commonsZipEntries = extractEntriesWithCommonsZip(tempZip);

        assertEquivalent(roundTripEntries, zipFileEntries);
        assertEquivalent(roundTripEntries, commonsZipEntries);

        byte[] commonsRezipped = commonsRezipEntries(roundTripEntries);
        List<EntryData> commonsRoundTrip =
            extractEntries(new ZipInputStream(new ByteArrayInputStream(commonsRezipped)));
        if (!commonsRoundTrip.isEmpty()) {
          assertEquivalent(roundTripEntries, commonsRoundTrip);
        }
      } finally {
        Files.deleteIfExists(tempZip);
      }
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

  private static Path writeTempZip(byte[] data) throws IOException {
    Path tempFile = Files.createTempFile("jazzer-zipfuzzer-", ".zip");
    Files.write(tempFile, data);
    return tempFile;
  }

  private static List<EntryData> extractEntriesWithCommonsInput(byte[] data) throws IOException {
    try (ZipArchiveInputStream zis = new ZipArchiveInputStream(new ByteArrayInputStream(data))) {
      List<EntryData> entries = new ArrayList<>();
      ZipArchiveEntry entry;
      int index = 0;
      while (index < MAX_ENTRIES && (entry = zis.getNextZipEntry()) != null) {
        entries.add(readEntry(zis, entry, index));
        index++;
      }
      return entries;
    }
  }

  private static List<EntryData> extractEntriesWithZipFile(Path zipPath) throws IOException {
    try (java.util.zip.ZipFile zipFile = new java.util.zip.ZipFile(zipPath.toFile())) {
      List<EntryData> entries = new ArrayList<>();
      int index = 0;
      Enumeration<? extends ZipEntry> enumeration = zipFile.entries();
      while (index < MAX_ENTRIES && enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        try (InputStream entryStream = zipFile.getInputStream(entry)) {
          entries.add(readEntry(entryStream, entry, index));
        }
        index++;
      }
      return entries;
    }
  }

  private static byte[] commonsRezipEntries(List<EntryData> entries) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipArchiveOutputStream zos = new ZipArchiveOutputStream(baos)) {
      for (EntryData entry : entries) {
        ZipArchiveEntry archiveEntry = new ZipArchiveEntry(entry.name);
        zos.putArchiveEntry(archiveEntry);
        zos.write(entry.data);
        zos.closeArchiveEntry();
      }
      zos.finish();
    }
    return baos.toByteArray();
  }

  private static List<EntryData> extractEntriesWithCommonsZip(Path zipPath) throws IOException {
    try (ZipFile zipFile = new ZipFile(zipPath.toFile())) {
      List<EntryData> entries = new ArrayList<>();
      int index = 0;
      Enumeration<ZipArchiveEntry> enumeration = zipFile.getEntries();
      while (index < MAX_ENTRIES && enumeration.hasMoreElements()) {
        ZipArchiveEntry entry = enumeration.nextElement();
        try (InputStream entryStream = zipFile.getInputStream(entry)) {
          entries.add(readEntry(entryStream, entry, index));
        }
        index++;
      }
      return entries;
    }
  }

  private static EntryData readEntry(InputStream entryStream, ZipEntry entry, int index)
      throws IOException {
    String name = entry.getName();
    if (name == null || name.isEmpty()) {
      name = "entry-" + index;
    }
    name = normalizeName(name);

    ByteArrayOutputStream entryData = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    int stored = 0;
    int read;
    while ((read = entryStream.read(buffer)) != -1) {
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

  private static String normalizeName(String name) {
    return name.replace('\\', '/');
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
