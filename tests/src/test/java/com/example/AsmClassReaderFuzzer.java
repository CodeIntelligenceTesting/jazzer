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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.params.provider.Arguments;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;

public final class AsmClassReaderFuzzer {

  public static void main(String[] args) {
    byte[] input = Base64.getDecoder().decode("IftdBAAAAAAAAgEAAAD/AAAAAAAAAAAAAAIBAAF/////");
    ClassReader reader = new ClassReader(input);
    ClassVisitor noOpVisitor = new ClassVisitor(Opcodes.ASM9) {};
    reader.accept(noOpVisitor, ClassReader.EXPAND_FRAMES);
  }

  private static final int MAX_CLASSFILE_BYTES = 1 << 20; // 1 MiB

  public static Stream<Arguments> asmFuzzer() {
    return Stream.of(Arguments.of());
  }

  public static class ExposingClassLoader extends ClassLoader {
    public Class<?> define(byte[] bytes, String name) {
      return super.defineClass(name, bytes, 0, bytes.length);
    }
  }

  public static void fuzzerTestOneInput(byte @NotNull [] data, @NotNull String name) {
    ExposingClassLoader cl = new ExposingClassLoader();
    try {
      Class<?> clazz = cl.define(data, name);
      clazz.getTypeName();
      clazz.getMethods();
      clazz.getRecordComponents();
      System.err.println(clazz.getName());
    } catch (Throwable ignored) {
    }
  }

  @FuzzTest
  void asmFuzzerbak(
      byte @NotNull [] data,
      boolean skipCode,
      boolean skipDebug,
      boolean skipFrames,
      boolean expandFrames) {
    //    byte[] bytecode = maybeExtractClass(data);
    if (data.length == 0 || data.length > MAX_CLASSFILE_BYTES) {
      return;
    }

    try {
      // Exercise basic metadata accessors to increase coverage without mutating the class.
      ClassReader reader = new ClassReader(data);
      reader.getClassName();
      reader.getSuperName();
      reader.getInterfaces();
      reader.getAccess();

      int options = 0;
      if (skipCode) {
        options |= ClassReader.SKIP_CODE;
      }
      if (skipDebug) {
        options |= ClassReader.SKIP_DEBUG;
      }
      if (skipFrames) {
        options |= ClassReader.SKIP_FRAMES;
      }
      if (expandFrames) {
        options |= ClassReader.EXPAND_FRAMES;
      }

      //        int ASM4 = 262144;
      //        int ASM5 = 327680;
      //        int ASM6 = 393216;
      //        int ASM7 = 458752;
      //        int ASM8 = 524288;
      //        int ASM9 = 589824;
      reader.accept(new ClassVisitor(Opcodes.ASM9) {}, options);
      //      int parsingOptions = computeParsingOptions(config);
      //      if (parsingOptions != ClassReader.EXPAND_FRAMES) {
      //        reader.accept(NO_OP_VISITOR, parsingOptions);
      //      }
    } catch (IllegalArgumentException
        | IndexOutOfBoundsException
        | NegativeArraySizeException
        | UnsupportedOperationException ignored) {
    }
  }

  private static int computeParsingOptions(int config) {
    int options = 0;
    if ((config & 0x01) != 0) {
      options |= ClassReader.SKIP_DEBUG;
    }
    if ((config & 0x02) != 0) {
      options |= ClassReader.SKIP_FRAMES;
    }
    if ((config & 0x04) != 0) {
      options |= ClassReader.SKIP_CODE;
    }
    boolean canExpandFrames = (options & ClassReader.SKIP_FRAMES) == 0;
    if ((config & 0x08) != 0 && canExpandFrames) {
      options |= ClassReader.EXPAND_FRAMES;
    }
    if (options == 0) {
      options = ClassReader.EXPAND_FRAMES;
    }
    return options;
  }

  private static ClassReader createReader(
      byte[] bytecode, int constructorSelector, int offsetSeed, int lengthSeed) throws IOException {
    switch (constructorSelector) {
      case 1:
        int offset = bytecode.length == 0 ? 0 : offsetSeed % bytecode.length;
        int available = bytecode.length - offset;
        if (available <= 0) {
          return new ClassReader(bytecode);
        }
        int len = lengthSeed % (available + 1);
        if (len == 0) {
          len = available;
        }
        return new ClassReader(bytecode, offset, len);
      case 2:
        return new ClassReader(new ByteArrayInputStream(bytecode));
      default:
        return new ClassReader(bytecode);
    }
  }

  private static byte[] maybeExtractClass(byte[] data) {
    if (data.length < 4 || data[0] != (byte) 0x50 || data[1] != (byte) 0x4B) {
      return data;
    }
    try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(data))) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        if (entry.isDirectory()) {
          zip.closeEntry();
          continue;
        }
        byte[] extracted = readZipEntry(zip);
        zip.closeEntry();
        if (extracted.length > 0 && extracted.length <= MAX_CLASSFILE_BYTES) {
          return extracted;
        }
      }
    } catch (IOException ignored) {
      // Ignore malformed archives and fall back to the raw data.
    }
    return data;
  }

  private static byte[] readZipEntry(ZipInputStream zip) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    boolean tooLarge = false;
    int total = 0;
    int read;
    while ((read = zip.read(buffer)) != -1) {
      if (tooLarge) {
        continue;
      }
      total += read;
      if (total > MAX_CLASSFILE_BYTES) {
        tooLarge = true;
      } else {
        out.write(buffer, 0, read);
      }
    }
    return tooLarge ? new byte[0] : out.toByteArray();
  }
}
