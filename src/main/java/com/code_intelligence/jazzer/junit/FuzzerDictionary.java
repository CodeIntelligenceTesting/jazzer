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

package com.code_intelligence.jazzer.junit;

import com.code_intelligence.jazzer.utils.Log;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.platform.commons.support.AnnotationSupport;

/**
 * Class that manages dictionaries for fuzz tests. The {@link DictionaryEntries} and {@link
 * DictionaryFile} annotations are added to {@link FuzzTest}s to indicate that these dictionaries
 * should be used for fuzzing this function. All tokens from all the sources will be added into a
 * single merged dictionary file as libfuzzer can only accept a single {@code -dict} flag.
 *
 * <p>Syntax for dictionaries can be found <a
 * href="https://llvm.org/docs/LibFuzzer.html#dictionaries">here</a>.
 */
class FuzzerDictionary {
  private static final String DICTIONARY_PREFIX = "jazzer-";
  private static final String DICTIONARY_SUFFIX = ".dict";

  /**
   * Create a temporary dictionary file for use during a fuzzing run based on the {@link
   * DictionaryEntries} and {@link DictionaryFile} annotations applied to {@code method}
   *
   * @param method The method which has 0 or more {@link DictionaryEntries} and {@link
   *     DictionaryFile} annotations applied
   * @return Optional containing the path to the created file, or nothing if {@code inline} and
   *     {@code files} are both empty
   * @throws IOException
   */
  static Optional<Path> createDictionaryFile(Method method) throws IOException {
    List<DictionaryEntries> inlineDictionaries =
        AnnotationSupport.findRepeatableAnnotations(method, DictionaryEntries.class);

    List<DictionaryFile> fileDictionaries =
        AnnotationSupport.findRepeatableAnnotations(method, DictionaryFile.class);

    return FuzzerDictionary.createDictionaryFile(
        inlineDictionaries, fileDictionaries, method.getDeclaringClass());
  }

  /**
   * Takes the lists of {@link DictionaryEntries} and {@link DictionaryFile} and creates the
   * temporary dictionary file based on their tokens
   *
   * @param inline list of {@link DictionaryEntries}
   * @param files list of {@link DictionaryFile}
   * @param declaringClass class containing the method with these annotations
   * @return Optional of dictionaryPath if created
   * @throws IOException
   */
  private static Optional<Path> createDictionaryFile(
      List<DictionaryEntries> inline, List<DictionaryFile> files, Class<?> declaringClass)
      throws IOException {
    int sources = inline.size() + files.size();
    if (sources == 0) {
      return Optional.empty();
    }

    Stream<String> joined =
        Stream.concat(getInlineTokens(inline), getFileTokens(files, declaringClass));

    Path p = Files.createTempFile(DICTIONARY_PREFIX, DICTIONARY_SUFFIX);
    p.toFile().deleteOnExit();
    Log.info(String.format("Creating merged dictionary from %d sources", sources));

    try (Writer w = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) {
      joined.forEach(
          token -> {
            try {
              w.append(token).append('\n');
            } catch (IOException e) {
              throw new UncheckedIOException(e);
            }
          });
    }
    return Optional.of(p);
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
        .map(DictionaryEntries::value)
        .flatMap(Arrays::stream)
        .map(FuzzerDictionary::escapeForDictionary);
  }

  static String escapeForDictionary(String rawString) {
    // https://llvm.org/docs/LibFuzzer.html#dictionaries
    String escapedString =
        // libFuzzer reads raw byte strings and assumes that every non-printable, non-space
        // character is escaped. Since our fuzzer generates UTF-8 strings, we decode the string with
        // UTF-8 and encode it to ISO-8859-1 (aka Latin-1), which results in a string with one byte
        // characters representing the UTF-8 encoded bytes.
        new String(rawString.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1)
            .chars()
            .flatMap(FuzzerDictionary::escapeByteForDictionary)
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    return '"' + escapedString + '"';
  }

  private static IntStream escapeByteForDictionary(int c) {
    // Escape all characters that are not printable ASCII or whitespace as well as the backslash
    // and double quote characters.
    // https://github.com/llvm/llvm-project/blob/675231eb09ca37a8b76f748c0b73a1e26604ff20/compiler-rt/lib/fuzzer/FuzzerUtil.cpp#L81
    if (c == '\\') {
      return IntStream.of('\\', '\\');
    } else if (c == '\"') {
      return IntStream.of('\\', '\"');
    } else if ((c < 32 && !Character.isWhitespace(c)) || c > 127) {
      return IntStream.of(
          '\\',
          'x',
          Character.toUpperCase(Character.forDigit(c >> 4, 16)),
          Character.toUpperCase(Character.forDigit(c & 0x0F, 16)));
    } else {
      return IntStream.of(c);
    }
  }

  /**
   * Gets the individual lines from each of the specified dictionary files
   *
   * @param files list of {@link DictionaryFile} annotations indicating which files to use
   * @param declaringClass class containing the method with these annotations
   * @return stream of all lines from each of the files
   */
  private static Stream<String> getFileTokens(List<DictionaryFile> files, Class<?> declaringClass) {
    return files.stream()
        .map(DictionaryFile::resourcePath)
        .map(resourcePath -> tokensFromResource(resourcePath, declaringClass))
        .flatMap(List::stream);
  }

  private static List<String> tokensFromResource(String resourcePath, Class<?> declaringClass) {
    try (InputStream resourceFile = declaringClass.getResourceAsStream(resourcePath)) {
      if (resourceFile == null) {
        throw new FileNotFoundException(resourcePath);
      }
      List<String> tokens;
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(resourceFile))) {
        tokens = reader.lines().collect(Collectors.toList());
      }
      return tokens;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
