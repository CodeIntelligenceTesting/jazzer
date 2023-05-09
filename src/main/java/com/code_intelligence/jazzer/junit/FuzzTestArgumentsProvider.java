// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.junit;

import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.Meta;
import com.code_intelligence.jazzer.driver.FuzzedDataProviderImpl;
import com.code_intelligence.jazzer.driver.Opt;
import com.code_intelligence.jazzer.mutation.ArgumentsMutator;
import java.io.ByteArrayInputStream;
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
import java.util.AbstractMap.SimpleEntry;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.AnnotationConsumer;

class FuzzTestArgumentsProvider implements ArgumentsProvider, AnnotationConsumer<FuzzTest> {
  private static final String INCORRECT_PARAMETERS_MESSAGE =
      "Methods annotated with @FuzzTest must take at least one parameter";

  private boolean invalidCorpusFilesPresent = false;
  private FuzzTest fuzzTest;

  @Override
  public void accept(FuzzTest annotation) {
    this.fuzzTest = annotation;
  }

  @Override
  public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext)
      throws IOException {
    // FIXME(fmeum): Calling this here feels like a hack. There should be a lifecycle hook that runs
    //  before the argument discovery for a ParameterizedTest is kicked off, but I haven't found
    //  one.
    FuzzTestExecutor.configureAndInstallAgent(extensionContext, fuzzTest.maxDuration());

    if (Utils.isFuzzing(extensionContext)) {
      // When fuzzing, supply a special set of arguments that our InvocationInterceptor uses as a
      // sign to start fuzzing.
      // FIXME: This is a hack that is needed only because there does not seem to be a way to
      //  communicate out of band that a certain invocation was triggered by a particular argument
      //  provider. We should get rid of this hack as soon as
      //  https://github.com/junit-team/junit5/issues/3282 has been addressed.
      return Stream.of(
          Utils.getMarkedArguments(extensionContext.getRequiredTestMethod(), "Fuzzing..."));
    } else {
      return provideSeedArguments(extensionContext);
    }
  }

  private Stream<? extends Arguments> provideSeedArguments(ExtensionContext extensionContext)
      throws IOException {
    Class<?> testClass = extensionContext.getRequiredTestClass();
    Method testMethod = extensionContext.getRequiredTestMethod();

    Stream<Map.Entry<String, byte[]>> rawSeeds =
        Stream.of(new SimpleImmutableEntry<>("<empty input>", new byte[0]));
    rawSeeds = Stream.concat(rawSeeds, walkInputs(testClass, testMethod));

    if (Utils.isCoverageAgentPresent()
        && Files.isDirectory(Utils.generatedCorpusPath(testClass, testMethod))) {
      rawSeeds = Stream.concat(rawSeeds,
          walkInputsInPath(Utils.generatedCorpusPath(testClass, testMethod), Integer.MAX_VALUE));
    }

    return adaptInputsForFuzzTest(extensionContext.getRequiredTestMethod(), rawSeeds).onClose(() -> {
      extensionContext.publishReportEntry(
          "No fuzzing has been performed, the fuzz test has only been executed on the fixed "
          + "set of inputs in the seed corpus.\n"
          + "To start fuzzing, run a test with the environment variable JAZZER_FUZZ set to a "
          + "non-empty value.");
      if (invalidCorpusFilesPresent) {
        extensionContext.publishReportEntry(
            "Some files in the seed corpus do not match the fuzz target signature.\n"
            + "This indicates that they were generated with a different signature and may cause "
            + "issues reproducing previous findings.");
      }
    });
  }

  /**
   * Maps the input file stream into a stream of {@link Arguments} objects, transforming the raw
   * bytes into the correct data type for the method.
   * <p>
   * Supported types are:
   * <ul>
   *   <li>{@code byte[]}</li>
   *   <li>{@code FuzzDataProvider}</li>
   *   <li>Any other types will attempt to be created using either Autofuzz or the experimental
   * mutator framework if {@link Opt}'s {@code experimentalMutator} is set</li>
   * </ul>
   * @param fuzzTestMethod the method being tested
   * @param rawSeeds a stream of file names -> file contents to use as test cases for {@code
   *     fuzzTestMethod}
   * @return a stream of {@link Arguments} containing the file name as the name of the test case and
   *     the transformed arguments
   */
  private Stream<? extends Arguments> adaptInputsForFuzzTest(
      Method fuzzTestMethod, Stream<Map.Entry<String, byte[]>> rawSeeds) {
    if (fuzzTestMethod.getParameterCount() == 0) {
      throw new IllegalArgumentException(INCORRECT_PARAMETERS_MESSAGE);
    }
    if (fuzzTestMethod.getParameterTypes()[0] == byte[].class) {
      return rawSeeds.map(e -> arguments(named(e.getKey(), e.getValue())));
    } else if (fuzzTestMethod.getParameterTypes()[0] == FuzzedDataProvider.class) {
      return rawSeeds.map(
          e -> arguments(named(e.getKey(), FuzzedDataProviderImpl.withJavaData(e.getValue()))));
    } else {
      // Use Autofuzz or mutation framework on the @FuzzTest method.
      Optional<ArgumentsMutator> argumentsMutator =
          Opt.experimentalMutator ? ArgumentsMutator.forMethod(fuzzTestMethod) : Optional.empty();

      return rawSeeds.map(e -> {
        Object[] args;
        if (argumentsMutator.isPresent()) {
          ArgumentsMutator mutator = argumentsMutator.get();
          boolean readExactly = mutator.read(new ByteArrayInputStream(e.getValue()));
          if (!readExactly) {
            invalidCorpusFilesPresent = true;
          }
          args = mutator.getArguments();
        } else {
          try (FuzzedDataProviderImpl data = FuzzedDataProviderImpl.withJavaData(e.getValue())) {
            // The Autofuzz FuzzTarget uses data to construct an instance of the test class before
            // it constructs the fuzz test arguments. We don't need the instance here, but still
            // generate it as that mutates the FuzzedDataProvider state.
            Meta meta = new Meta(fuzzTestMethod.getDeclaringClass());
            meta.consumeNonStatic(data, fuzzTestMethod.getDeclaringClass());
            args = meta.consumeArguments(data, fuzzTestMethod, null);
          }
        }
        // In order to name the subtest, we name the first argument. All other arguments are
        // passed in unchanged.
        args[0] = named(e.getKey(), args[0]);
        return arguments(args);
      });
    }
  }

  /**
   * Used in regression mode to get test cases for the associated {@code testMethod}
   * This will return a stream of files consisting of:
   * <ul>
   * <li>{@code resources/<classpath>/<testClass name>Inputs/*}</li>
   * <li>{@code resources/<classpath>/<testClass name>Inputs/<testMethod name>/**}</li>
   * </ul>
   * Or the equivalent behavior on resources inside a jar file.
   * <p>
   * Note that the first {@code <testClass name>Inputs} path will not recursively search all
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

      return Stream
          .concat(walkClassInputs(classPathInJar), walkTestInputs(classPathInJar, testMethod))
          .onClose(() -> {
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
   * @param classInputsPath the path of the class being tested, used as the base path where the test
   *     method's directory
   *                        should be
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
   * @param path the path to search to files
   * @return a stream of all files (without directories) within {@code path}. If {@code path} is not
   *     found, an empty
   *    stream is returned.
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
   * @param path the path to walk
   * @param depth the maximum depth of subdirectories to search from within {@code path}. 1
   *     indicates it should return
   *              only the files directly in {@code path} and not search any of its subdirectories
   * @return a stream of file name -> file contents as a raw byte array
   * @throws IOException can be thrown by the call to {@link Files#find(Path, int, BiPredicate,
   *     FileVisitOption...)}
   */
  private static Stream<Map.Entry<String, byte[]>> walkInputsInPath(Path path, int depth)
      throws IOException {
    // @ParameterTest automatically closes Streams and AutoCloseable instances.
    // noinspection resource
    return Files
        .find(path, depth,
            (fileOrDir, basicFileAttributes)
                -> !basicFileAttributes.isDirectory(),
            FileVisitOption.FOLLOW_LINKS)
        // JUnit identifies individual runs of a `@ParameterizedTest` via their invocation number.
        // In order to get reproducible behavior e.g. when trying to debug a particular input, all
        // inputs thus have to be provided in deterministic order.
        .sorted()
        .map(file -> new SimpleEntry<>(file.getFileName().toString(), readAllBytesUnchecked(file)));
  }

  private static byte[] readAllBytesUnchecked(Path path) {
    try {
      return Files.readAllBytes(path);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
