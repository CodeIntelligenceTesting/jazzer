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

package com.code_intelligence.jazzer.android;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class DexFileManager {
  private static final int MAX_READ_LENGTH = 2000000;

  public static byte[] getBytecodeFromDex(String jarPath, String dexFile) throws IOException {
    try (JarFile jarFile = new JarFile(jarPath)) {
      JarEntry entry =
          jarFile.stream()
              .filter(jarEntry -> jarEntry.getName().equals(dexFile))
              .findFirst()
              .orElse(null);

      if (entry == null) {
        throw new IOException("Could not find dex file: " + dexFile);
      }

      try (InputStream is = jarFile.getInputStream(entry)) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] buffer = new byte[64 * 104 * 1024];
        int read;
        while ((read = is.read(buffer)) != -1) {
          out.write(buffer, 0, read);
        }

        return out.toByteArray();
      }
    }
  }

  public static String[] getDexFilesForJar(String jarpath) throws IOException {
    try (JarFile jarFile = new JarFile(jarpath)) {
      return jarFile.stream()
          .map(JarEntry::getName)
          .filter(entry -> entry.endsWith(".dex"))
          .toArray(String[]::new);
    }
  }
}
