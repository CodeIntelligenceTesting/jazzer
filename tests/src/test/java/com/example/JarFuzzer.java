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
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.commons.compress.archivers.jar.JarArchiveEntry;
import org.apache.commons.compress.archivers.jar.JarArchiveInputStream;
import org.apache.commons.compress.archivers.jar.JarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;

public class JarFuzzer {
  private static final int MAX_ENTRIES = 16;
  private static final int MAX_ENTRY_BYTES = 1 << 17; // 128 KiB per entry
  private static final int MAX_MANIFEST_BYTES = 1 << 16;

  public static void fuzzerTestOneInput(byte[] data) throws IOException {
    try {
      JarArchive original = extractArchive(data);
      if (original.entries.isEmpty()) {
        return;
      }

      byte[] jdkRezipped = rezipArchive(original);
      JarArchive jdkRoundTrip = extractArchive(jdkRezipped);
      if (jdkRoundTrip.entries.isEmpty()) {
        return;
      }

      assertManifestEquivalent(original.manifestBytes, jdkRoundTrip.manifestBytes);
      assertEquivalent(original.entries, jdkRoundTrip.entries);

      List<EntryData> jdkEntriesNoManifest = removeManifestEntries(jdkRoundTrip.entries);

      List<EntryData> commonsStreamEntries =
          removeManifestEntries(extractEntriesWithCommonsInput(jdkRezipped));
      if (!commonsStreamEntries.isEmpty()) {
        assertEquivalent(jdkEntriesNoManifest, commonsStreamEntries);
      }

      Path tempJar = writeTempJar(jdkRezipped);
      try {
        List<EntryData> jarFileEntries = removeManifestEntries(extractEntriesWithJarFile(tempJar));
        List<EntryData> commonsJarEntries =
            removeManifestEntries(extractEntriesWithCommonsJarFile(tempJar));

        assertEquivalent(jdkEntriesNoManifest, jarFileEntries);
        assertEquivalent(jdkEntriesNoManifest, commonsJarEntries);

        byte[] commonsRezipped = commonsRezipArchive(jdkRoundTrip);
        JarArchive commonsRoundTrip = extractArchive(commonsRezipped);
        if (!commonsRoundTrip.entries.isEmpty()) {
          assertManifestEquivalent(jdkRoundTrip.manifestBytes, commonsRoundTrip.manifestBytes);
          assertEquivalent(jdkEntriesNoManifest, removeManifestEntries(commonsRoundTrip.entries));
        }
      } finally {
        Files.deleteIfExists(tempJar);
      }
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }

  private static JarArchive extractArchive(byte[] data) throws IOException {
    try (JarInputStream jis = new JarInputStream(new ByteArrayInputStream(data))) {
      byte[] manifestBytes = readManifest(jis.getManifest());
      List<EntryData> entries = new ArrayList<>();
      JarEntry entry;
      int index = 0;
      while (index < MAX_ENTRIES && (entry = jis.getNextJarEntry()) != null) {
        EntryData dataEntry = readEntry(jis, entry.getName(), entry.isDirectory(), index);
        if (dataEntry != null) {
          entries.add(dataEntry);
        }
        jis.closeEntry();
        index++;
      }
      return new JarArchive(entries, manifestBytes);
    }
  }

  private static byte[] rezipArchive(JarArchive archive) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    boolean hasManifestEntry = hasManifestEntry(archive.entries);
    JarOutputStream jos;
    if (archive.manifestBytes != null && !hasManifestEntry) {
      jos =
          new JarOutputStream(baos, new Manifest(new ByteArrayInputStream(archive.manifestBytes)));
    } else {
      jos = new JarOutputStream(baos);
    }
    try {
      for (EntryData entry : archive.entries) {
        JarEntry jarEntry = new JarEntry(entry.name);
        jos.putNextEntry(jarEntry);
        jos.write(entry.data);
        jos.closeEntry();
      }
    } finally {
      jos.close();
    }
    return baos.toByteArray();
  }

  private static List<EntryData> extractEntriesWithCommonsInput(byte[] data) throws IOException {
    try (JarArchiveInputStream jis = new JarArchiveInputStream(new ByteArrayInputStream(data))) {
      List<EntryData> entries = new ArrayList<>();
      JarArchiveEntry entry;
      int index = 0;
      while (index < MAX_ENTRIES && (entry = jis.getNextJarEntry()) != null) {
        EntryData dataEntry = readEntry(jis, entry.getName(), entry.isDirectory(), index);
        if (dataEntry != null) {
          entries.add(dataEntry);
        }
        index++;
      }
      return entries;
    }
  }

  private static Path writeTempJar(byte[] data) throws IOException {
    Path tempFile = Files.createTempFile("jazzer-jarfuzzer-", ".jar");
    Files.write(tempFile, data);
    return tempFile;
  }

  private static List<EntryData> extractEntriesWithJarFile(Path path) throws IOException {
    try (JarFile jarFile = new JarFile(path.toFile())) {
      List<EntryData> entries = new ArrayList<>();
      Enumeration<JarEntry> enumeration = jarFile.entries();
      int index = 0;
      while (index < MAX_ENTRIES && enumeration.hasMoreElements()) {
        JarEntry entry = enumeration.nextElement();
        try (InputStream entryStream = jarFile.getInputStream(entry)) {
          EntryData dataEntry = readEntry(entryStream, entry.getName(), entry.isDirectory(), index);
          if (dataEntry != null) {
            entries.add(dataEntry);
          }
        }
        index++;
      }
      return entries;
    }
  }

  private static List<EntryData> extractEntriesWithCommonsJarFile(Path path) throws IOException {
    try (ZipFile jarFile = new ZipFile(path.toFile())) {
      List<EntryData> entries = new ArrayList<>();
      Enumeration<ZipArchiveEntry> enumeration = jarFile.getEntries();
      int index = 0;
      while (index < MAX_ENTRIES && enumeration.hasMoreElements()) {
        ZipArchiveEntry entry = enumeration.nextElement();
        try (InputStream entryStream = jarFile.getInputStream(entry)) {
          EntryData dataEntry = readEntry(entryStream, entry.getName(), entry.isDirectory(), index);
          if (dataEntry != null) {
            entries.add(dataEntry);
          }
        }
        index++;
      }
      return entries;
    }
  }

  private static byte[] commonsRezipArchive(JarArchive archive) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    boolean hasManifestEntry = hasManifestEntry(archive.entries);
    try (JarArchiveOutputStream jos = new JarArchiveOutputStream(baos)) {
      if (archive.manifestBytes != null && !hasManifestEntry) {
        JarArchiveEntry manifestEntry = new JarArchiveEntry("META-INF/MANIFEST.MF");
        jos.putArchiveEntry(manifestEntry);
        jos.write(archive.manifestBytes);
        jos.closeArchiveEntry();
      }
      for (EntryData entry : archive.entries) {
        JarArchiveEntry archiveEntry = new JarArchiveEntry(entry.name);
        jos.putArchiveEntry(archiveEntry);
        jos.write(entry.data);
        jos.closeArchiveEntry();
      }
      jos.finish();
    }
    return baos.toByteArray();
  }

  private static EntryData readEntry(
      InputStream entryStream, String rawName, boolean isDirectory, int index) throws IOException {
    if (isDirectory) {
      return null;
    }
    String name = rawName;
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
      } else {
        break;
      }
    }
    return new EntryData(name, entryData.toByteArray());
  }

  private static boolean hasManifestEntry(List<EntryData> entries) {
    for (EntryData entry : entries) {
      if ("META-INF/MANIFEST.MF".equals(entry.name)) {
        return true;
      }
    }
    return false;
  }

  private static List<EntryData> removeManifestEntries(List<EntryData> entries) {
    boolean found = false;
    for (EntryData entry : entries) {
      if ("META-INF/MANIFEST.MF".equals(entry.name)) {
        found = true;
        break;
      }
    }
    if (!found) {
      return entries;
    }
    List<EntryData> filtered = new ArrayList<>(entries.size());
    for (EntryData entry : entries) {
      if (!"META-INF/MANIFEST.MF".equals(entry.name)) {
        filtered.add(entry);
      }
    }
    return filtered;
  }

  private static byte[] readManifest(Manifest manifest) throws IOException {
    if (manifest == null) {
      return null;
    }
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    manifest.write(baos);
    if (baos.size() > MAX_MANIFEST_BYTES) {
      return null;
    }
    return baos.toByteArray();
  }

  private static void assertEquivalent(List<EntryData> expected, List<EntryData> actual) {
    if (expected.size() != actual.size()) {
      //      logEntrySummary("expected", expected);
      //      logEntrySummary("actual", actual);
      throw new AssertionError("Entry count mismatch: " + expected.size() + " vs " + actual.size());
    }

    for (int i = 0; i < expected.size(); i++) {
      EntryData exp = expected.get(i);
      EntryData act = actual.get(i);
      if (!exp.name.equals(act.name)) {
        //        logEntrySummary("expected", expected);
        //        logEntrySummary("actual", actual);
        throw new AssertionError(
            String.format("Entry %d name mismatch: %s vs %s", i, exp.name, act.name));
      }
      if (!Arrays.equals(exp.data, act.data)) {
        //        logEntrySummary("expected", expected);
        //        logEntrySummary("actual", actual);
        throw new AssertionError("Entry " + exp.name + " payload mismatch");
      }
    }
  }

  private static void assertManifestEquivalent(byte[] expected, byte[] actual) {
    if (expected == null && actual == null) {
      return;
    }
    if (expected == null || actual == null) {
      throw new AssertionError("Manifest presence mismatch");
    }
    if (!Arrays.equals(expected, actual)) {
      throw new AssertionError("Manifest payload mismatch");
    }
  }

  private static String normalizeName(String name) {
    return name.replace('\\', '/');
  }

  private static void logEntrySummary(String label, List<EntryData> entries) {
    StringBuilder builder = new StringBuilder();
    builder
        .append("[JarFuzzer] ")
        .append(label)
        .append(" entries (")
        .append(entries.size())
        .append("): ");
    int limit = Math.min(entries.size(), 10);
    for (int i = 0; i < limit; i++) {
      builder.append(entries.get(i).name);
      if (i < limit - 1) {
        builder.append(", ");
      }
    }
    if (entries.size() > limit) {
      builder.append(" ...");
    }
    System.err.println(builder);
  }

  private static final class JarArchive {
    final List<EntryData> entries;
    final byte[] manifestBytes;

    JarArchive(List<EntryData> entries, byte[] manifestBytes) {
      this.entries = entries;
      this.manifestBytes = manifestBytes;
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
