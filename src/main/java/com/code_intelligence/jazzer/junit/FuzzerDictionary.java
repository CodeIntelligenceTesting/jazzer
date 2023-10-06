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
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.commons.util.ClassLoaderUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Class that manages dictionaries for fuzz tests. The {@link DictionaryEntries} and {@link
 * DictionaryFile} annotations are added to {@link FuzzTest}s to indicate that these
 * dictionaries should be used for fuzzing this function. All tokens from all the sources will be
 * added into a single merged dictionary file as libfuzzer can only accept a single {@code -dict}
 * flag.
 *
 * <p>Syntax for dictionaries can be found <a
 * href="https://llvm.org/docs/LibFuzzer.html#dictionaries">here</a>.
 */
class FuzzerDictionary {
  private static final String DICTIONARY_PREFIX = "jazzer-";
  private static final String DICTIONARY_SUFFIX = ".dict";

  static Optional<String> createDictionaryFile(ExtensionContext context) throws IOException {
    List<DictionaryEntries> inlineDictionaries =
            AnnotationSupport.findRepeatableAnnotations(
                    context.getRequiredTestMethod(), DictionaryEntries.class);

    List<DictionaryFile> fileDictionaries =
            AnnotationSupport.findRepeatableAnnotations(
                    context.getRequiredTestMethod(), DictionaryFile.class);

    return FuzzerDictionary.createDictionaryFile(inlineDictionaries, fileDictionaries);
  }

  /**
   * Create a temporary dictionary file for use during a fuzzing run based on the tokens found
   * within {@code inline} and {@code files}.
   *
   * @param inline List of {@link DictionaryEntries} annotations that directly hold static token values
   *     to use in the dictionary
   * @param files List of {@link DictionaryFile} annotations that reference dictionary files to
   *     include
   * @return Optional containing the path to the created file, or nothing if {@code inline} and
   *     {@code files} are both empty
   * @throws IOException
   */
  private static Optional<String> createDictionaryFile(
      List<DictionaryEntries> inline, List<DictionaryFile> files) throws IOException {
    int sources = inline.size() + files.size();
    if (sources == 0) {
      return Optional.empty();
    }

    Stream<String> joined = Stream.concat(getInlineTokens(inline), getFileTokens(files));

    File f = File.createTempFile(DICTIONARY_PREFIX, DICTIONARY_SUFFIX);
    f.deleteOnExit();
    Log.info(String.format("Creating merged dictionary from %d sources", sources));

    try (OutputStream out = Files.newOutputStream(f.toPath())) {
      joined.forEach(
          (token) -> {
            try {
              // the tokens will come in without newlines attached, so we append them here before
              // writing
              String line = token.concat("\n");
              out.write(line.getBytes());
            } catch (IOException e) {
              throw new UncheckedIOException(e);
            }
          });
    }
    return Optional.of(f.getPath());
  }

  /**
   * Gets the inlined arrays from each annotation, flattens them into a single stream, and wraps the
   * elements in double quotes to comply with libfuzzer's dictionary syntax
   *
   * @param inline List of {@link DictionaryEntries} annotations to extract from
   * @return stream of all the tokens from each of the elements of {@code inline}
   */
  private static Stream<String> getInlineTokens(List<DictionaryEntries> inline) {
    return inline.stream()
        .map(DictionaryEntries::tokens)
        .flatMap(Arrays::stream)
        .map(token -> String.format("\"%s\"", token));
  }

  /**
   * Gets the individual lines from each of the specified dictionary files
   *
   * @param files List of {@link DictionaryFile} annotations indicating which files to use
   * @return stream of all lines from each of the files
   */
  private static Stream<String> getFileTokens(List<DictionaryFile> files) {
    return files.stream()
        .map(DictionaryFile::resourcePath)
        .map(FuzzerDictionary::tokensFromFile)
        .flatMap(List::stream);
  }

  private static List<String> tokensFromFile(String path) {
    try (InputStream resourceFile = ClassLoaderUtils.class.getResourceAsStream(path)) {
      if (resourceFile == null) {
        throw new FileNotFoundException(path);
      }
      BufferedReader reader = new BufferedReader(new InputStreamReader(resourceFile));
      // I think returning just reader.lines() results in the file stream being closed before it's
      // read, so we immediately read the file and collect the lines into a list
      return reader.lines().collect(Collectors.toList());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}