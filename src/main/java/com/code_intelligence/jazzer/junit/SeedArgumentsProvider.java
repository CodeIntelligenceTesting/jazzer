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

import static com.code_intelligence.jazzer.junit.Utils.isFuzzing;
import static com.code_intelligence.jazzer.junit.Utils.runFromCommandLine;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

class SeedArgumentsProvider implements ArgumentsProvider {
  @Override
  public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext)
      throws IOException {
    if (runFromCommandLine(extensionContext) && isFuzzing(extensionContext)) {
      // libFuzzer always runs on the file-based seeds first anyway and the additional visual
      // indication provided by test invocations for seeds isn't effective on the command line, so
      // we skip these invocations.
      return Stream.empty();
    }

    Class<?> testClass = extensionContext.getRequiredTestClass();
    Method testMethod = extensionContext.getRequiredTestMethod();

    Stream<Map.Entry<String, byte[]>> rawSeeds =
        Stream.of(new SimpleImmutableEntry<>("<empty input>", new byte[0]));
    rawSeeds = Stream.concat(rawSeeds, walkInputs(testClass, testMethod));

    if (Utils.isGatheringCoverage()) {
      Path generatedCorpusPath = Utils.generatedCorpusPath(testClass, testMethod);
      // Generated corpus entries are automatically created and should be available,
      // except when no fuzzing was performed until now.
      if (Files.isDirectory(generatedCorpusPath)) {
        rawSeeds =
            Stream.concat(rawSeeds, walkInputsInPath(generatedCorpusPath, Integer.MAX_VALUE));
      }
      // Also add additionally specified files and directories to the input list,
      // e.g. cifuzz uses this feature to specify additional seed directories.
      for (String filesOrDir : Utils.getCorpusFilesOrDirs(extensionContext)) {
        rawSeeds =
            Stream.concat(rawSeeds, walkInputsInPath(Paths.get(filesOrDir), Integer.MAX_VALUE));
      }
    }

    SeedSerializer serializer = SeedSerializer.of(testMethod);
    return rawSeeds
        .map(
            entry -> {
              Object[] args = serializer.read(entry.getValue());
              args[0] = named(entry.getKey(), args[0]);
              return arguments(args);
            })
        .onClose(
            () -> {
              if (!isFuzzing(extensionContext)) {
                extensionContext.publishReportEntry(
                    "No fuzzing has been performed, the fuzz test has only been executed on the"
                        + " fixed set of inputs in the seed corpus.\n"
                        + "To start fuzzing, run a test with the environment variable JAZZER_FUZZ"
                        + " set to a non-empty value.");
              }
            });
  }

  /**
   * Used in regression mode to get test cases for the associated {@code testMethod} This will
   * return a stream of files consisting of:
   *
   * <ul>
   *   <li>{@code resources/<classpath>/<testClass name>Inputs/*}
   *   <li>{@code resources/<classpath>/<testClass name>Inputs/<testMethod name>/**}
   * </ul>
   *
   * Or the equivalent behavior on resources inside a jar file.
   *
   * <p>Note that the first {@code <testClass name>Inputs} path will not recursively search all
   * directories but only gives files in that directory whereas the {@code <testMethod name>}
   * directory is searched recursively. This allows for multiple tests to share inputs without
   * needing to explicitly copy them into each test's directory.
   *
   * @param testClass the class of the test being run
   * @param testMethod the test function being run
   * @return a stream of findings files to use as inputs for the test function
   */
  private Stream<Map.Entry<String, byte[]>> walkInputs(Class<?> testClass, Method testMethod)
      throws IOException {
    URL classInputsDirUrl = testClass.getResource(Utils.inputsDirectoryResourcePath(testClass));

    if (classInputsDirUrl == null) {
      return Stream.empty();
    }
    URI classInputsDirUri;
    try {
      classInputsDirUri = classInputsDirUrl.toURI();
    } catch (URISyntaxException e) {
      throw new IOException("Failed to open inputs resource directory: " + classInputsDirUrl, e);
    }
    if (classInputsDirUri.getScheme().equals("file")) {
      // The test is executed from class files, which usually happens when run from inside an IDE.
      Path classInputsPath = Paths.get(classInputsDirUri);

      return Stream.concat(
          walkClassInputs(classInputsPath), walkTestInputs(classInputsPath, testMethod));

    } else if (classInputsDirUri.getScheme().equals("jar")) {
      FileSystem jar = FileSystems.newFileSystem(classInputsDirUri, new HashMap<>());
      // inputsDirUrl looks like this:
      // file:/tmp/testdata/ExampleFuzzTest_deploy.jar!/com/code_intelligence/jazzer/junit/testdata/ExampleFuzzTestInputs
      String pathInJar =
          classInputsDirUrl.getFile().substring(classInputsDirUrl.getFile().indexOf('!') + 1);

      Path classPathInJar = jar.getPath(pathInJar);

      return Stream.concat(
              walkClassInputs(classPathInJar), walkTestInputs(classPathInJar, testMethod))
          .onClose(
              () -> {
                try {
                  jar.close();
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });
    } else {
      throw new IOException(
          "Unsupported protocol for inputs resource directory: " + classInputsDirUrl);
    }
  }

  /**
   * Walks over the inputs for the method being tested, recurses into subdirectories
   *
   * @param classInputsPath the path of the class being tested, used as the base path where the test
   *     method's directory should be
   * @param testMethod the method being tested
   * @return a stream of all files under {@code <classInputsPath>/<testMethod name>}
   * @throws IOException can be thrown by the underlying call to {@link Files#find}
   */
  private static Stream<Map.Entry<String, byte[]>> walkTestInputs(
      Path classInputsPath, Method testMethod) throws IOException {
    Path testInputsPath = classInputsPath.resolve(testMethod.getName());
    try {
      return walkInputsInPath(testInputsPath, Integer.MAX_VALUE);
    } catch (NoSuchFileException e) {
      return Stream.empty();
    }
  }

  /**
   * Walks over the inputs for the class being tested. Does not recurse into subdirectories
   *
   * @param path the path to search to files
   * @return a stream of all files (without directories) within {@code path}. If {@code path} is not
   *     found, an empty stream is returned.
   * @throws IOException can be thrown by the underlying call to {@link Files#find}
   */
  private static Stream<Map.Entry<String, byte[]>> walkClassInputs(Path path) throws IOException {
    try {
      // using a depth of 1 will get all files within the given path but does not recurse into
      // subdirectories
      return walkInputsInPath(path, 1);
    } catch (NoSuchFileException e) {
      return Stream.empty();
    }
  }

  /**
   * Gets a sorted stream of all files (without directories) within under the given {@code path}
   *
   * @param path the path to walk
   * @param depth the maximum depth of subdirectories to search from within {@code path}. 1
   *     indicates it should return only the files directly in {@code path} and not search any of
   *     its subdirectories
   * @return a stream of file name -> file contents as a raw byte array
   * @throws IOException can be thrown by the call to {@link Files#find(Path, int, BiPredicate,
   *     FileVisitOption...)}
   */
  private static Stream<Map.Entry<String, byte[]>> walkInputsInPath(Path path, int depth)
      throws IOException {
    // @ParameterTest automatically closes Streams and AutoCloseable instances.
    // noinspection resource
    return Files.find(
            path,
            depth,
            (fileOrDir, basicFileAttributes) -> !basicFileAttributes.isDirectory(),
            FileVisitOption.FOLLOW_LINKS)
        // JUnit identifies individual runs of a `@ParameterizedTest` via their invocation number.
        // In order to get reproducible behavior e.g. when trying to debug a particular input, all
        // inputs thus have to be provided in deterministic order.
        .sorted()
        .map(
            file ->
                new SimpleImmutableEntry<>(
                    file.getFileName().toString(), readAllBytesUnchecked(file)));
  }

  private static byte[] readAllBytesUnchecked(Path path) {
    try {
      return Files.readAllBytes(path);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
