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

package com.code_intelligence.jazzer.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public final class ZipUtils {
  private ZipUtils() {}

  public static Set<String> mergeZipToZip(String src, ZipOutputStream zos, Set<String> skipFiles)
      throws IOException {
    HashSet<String> filesAdded = new HashSet<>();
    try (JarFile jarFile = new JarFile(src)) {
      // Copy entries from src to dst (jarFile to ZipOutputStream)
      Enumeration<JarEntry> allEntries = jarFile.entries();
      while (allEntries.hasMoreElements()) {
        JarEntry entry = allEntries.nextElement();
        if (skipFiles != null && skipFiles.contains(entry.getName())) {
          continue;
        }

        zos.putNextEntry(new ZipEntry(entry.getName()));
        try (InputStream is = jarFile.getInputStream(entry)) {
          byte[] buf = new byte[1024];
          int i = 0;
          while ((i = is.read(buf)) != -1) {
            zos.write(buf, 0, i);
          }

          zos.closeEntry();
          filesAdded.add(entry.getName());
        }
      }
    }

    return filesAdded;
  }

  public static Set<String> mergeDirectoryToZip(
      String src, ZipOutputStream zos, Set<String> skipFiles)
      throws IllegalArgumentException, IOException {
    HashSet<String> filesAdded = new HashSet<>();
    File sourceDir = new File(src);
    if (!sourceDir.isDirectory()) {
      throw new IllegalArgumentException("Argument src must be a directory. Path provided: " + src);
    }

    Files.walkFileTree(
        sourceDir.toPath(),
        new SimpleFileVisitor<Path>() {
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
              throws IOException {
            String zipPath = sourceDir.toPath().relativize(file).toString();
            if (skipFiles.stream().anyMatch(zipPath::endsWith)) {
              return FileVisitResult.CONTINUE;
            }

            zos.putNextEntry(new ZipEntry(zipPath));
            Files.copy(file, zos);
            filesAdded.add(zipPath);
            return FileVisitResult.CONTINUE;
          }
        });

    return filesAdded;
  }

  public static void extractFile(String srcZip, String targetFile, String outputFilePath)
      throws IOException {
    try (OutputStream out = new FileOutputStream(outputFilePath);
        ZipInputStream zis = new ZipInputStream(new FileInputStream(srcZip)); ) {
      ZipEntry ze = zis.getNextEntry();
      while (ze != null) {
        if (ze.getName().equals(targetFile)) {
          byte[] buf = new byte[1024];
          int read = 0;

          while ((read = zis.read(buf)) > -1) {
            out.write(buf, 0, read);
          }

          out.close();
          break;
        }

        ze = zis.getNextEntry();
      }
    }
  }
}
