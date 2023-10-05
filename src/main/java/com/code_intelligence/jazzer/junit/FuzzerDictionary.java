/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.junit;

import com.code_intelligence.jazzer.utils.Log;
import java.io.*;
import java.lang.annotation.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.platform.commons.util.ClassLoaderUtils;

public class FuzzerDictionary {
  private static final String DICTIONARY_PREFIX = "jazzer-";
  private static final String DICTIONARY_SUFFIX = ".dict";

  public static String createMergedFile(List<WithDictionary> inline, List<WithDictionaryFile> files)
      throws IOException {
    // https://llvm.org/docs/LibFuzzer.html#dictionaries
    Stream<String> inlineTokens =
        inline.stream()
            .map(WithDictionary::tokens)
            .flatMap(Arrays::stream)
            .map((token) -> String.format("\"%s\"", token));
    Stream<String> fileTokens =
        files.stream()
            .map(WithDictionaryFile::resourcePath)
            .map(FuzzerDictionary::tokensFromFile)
            .flatMap(List::stream);
    Stream<String> joined = Stream.concat(inlineTokens, fileTokens);

    File f = File.createTempFile(DICTIONARY_PREFIX, DICTIONARY_SUFFIX);
    f.deleteOnExit();

    int sources = inline.size() + files.size();
    Log.info(String.format("Creating merged dictionary from %d sources", sources));

    try (OutputStream out = Files.newOutputStream(f.toPath())) {
      joined.forEach(
          (token) -> {
            try {
              String line = token.concat("\n");
              out.write(line.getBytes());
            } catch (IOException e) {
              throw new RuntimeException("error writing to dictionary file");
            }
          });
    }
    return f.getPath();
  }

  private static List<String> tokensFromFile(String path) {
    try (InputStream resourceFile = ClassLoaderUtils.class.getResourceAsStream(path)) {
      if (resourceFile == null) {
        throw new FileNotFoundException(path);
      }
      BufferedReader reader = new BufferedReader(new InputStreamReader(resourceFile));
      // I think returning just reader.lines results in the file stream being closed before it's
      // read so we immediately
      // read the file and collect the lines into a list
      return reader.lines().collect(Collectors.toList());
    } catch (IOException e) {
      throw new RuntimeException("error reading dictionary file", e);
    }
  }

  @Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  @Repeatable(Dictionaries.class)
  public @interface WithDictionary {
    String[] tokens();
  }

  @Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  @Repeatable(DictionaryFiles.class)
  public @interface WithDictionaryFile {
    String resourcePath();
  }

  @Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  public @interface Dictionaries {
    WithDictionary[] value();
  }

  @Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  public @interface DictionaryFiles {
    WithDictionaryFile[] value();
  }
}
