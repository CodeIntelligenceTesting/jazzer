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
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.AnnotationConsumer;

class RegressionTestArgumentProvider implements ArgumentsProvider, AnnotationConsumer<FuzzTest> {
  private static final String INCORRECT_PARAMETERS_MESSAGE =
      "Methods annotated with @FuzzTest must take at least one parameter";
  private FuzzTest annotation;

  @Override
  public void accept(FuzzTest annotation) {
    this.annotation = annotation;
  }

  @Override
  public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext)
      throws IOException {
    Class<?> testClass = extensionContext.getRequiredTestClass();
    Stream<Map.Entry<String, byte[]>> rawSeeds = Stream.concat(
        Stream.of(new SimpleEntry<>("<empty input>", new byte[] {})), walkSeedCorpus(testClass));
    if (Utils.isCoverageAgentPresent() && Files.isDirectory(Utils.generatedCorpusPath(testClass))) {
      rawSeeds = Stream.concat(rawSeeds, walkSeedsInPath(Utils.generatedCorpusPath(testClass)));
    }
    return adaptSeedsForFuzzTest(extensionContext.getRequiredTestMethod(), rawSeeds);
  }

  private Stream<? extends Arguments> adaptSeedsForFuzzTest(
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
      // Use Autofuzz on the @FuzzTest method.
      return rawSeeds.map(e -> {
        try (FuzzedDataProviderImpl data = FuzzedDataProviderImpl.withJavaData(e.getValue())) {
          // The Autofuzz FuzzTarget uses data to construct an instance of the test class before it
          // constructs the fuzz test arguments. We don't need the instance here, but still generate
          // it as that mutates the FuzzedDataProvider state.
          Meta meta = new Meta(fuzzTestMethod.getDeclaringClass());
          meta.consumeNonStatic(data, fuzzTestMethod.getDeclaringClass());
          Object[] args = meta.consumeArguments(data, fuzzTestMethod, null);
          // In order to name the subtest, we name the first argument. All other arguments are
          // passed in unchanged.
          args[0] = named(e.getKey(), args[0]);
          return arguments(args);
        }
      });
    }
  }

  private Stream<Map.Entry<String, byte[]>> walkSeedCorpus(Class<?> testClass) throws IOException {
    String seedCorpusArg = annotation.seedCorpus();
    String seedCorpusPath =
        seedCorpusArg.isEmpty() ? Utils.defaultSeedCorpusPath(testClass) : seedCorpusArg;
    URL seedCorpusUrl = testClass.getResource(seedCorpusPath);
    if (seedCorpusUrl == null) {
      return Stream.empty();
    }
    URI seedCorpusUri;
    try {
      seedCorpusUri = seedCorpusUrl.toURI();
    } catch (URISyntaxException e) {
      throw new IOException("Failed to open seed corpus resource directory: " + seedCorpusUrl, e);
    }
    if (seedCorpusUri.getScheme().equals("file")) {
      // The test is executed from class files, which usually happens when run from inside an IDE.
      return walkSeedsInPath(Paths.get(seedCorpusUri));
    } else if (seedCorpusUri.getScheme().equals("jar")) {
      FileSystem jar = FileSystems.newFileSystem(seedCorpusUri, new HashMap<>());
      // seedCorpusUrl looks like this:
      // file:/tmp/testdata/ExampleFuzzTest_deploy.jar!/com/code_intelligence/jazzer/junit/testdata/ExampleFuzzTestSeedCorpus
      String pathInJar =
          seedCorpusUrl.getFile().substring(seedCorpusUrl.getFile().indexOf('!') + 1);
      return walkSeedsInPath(jar.getPath(pathInJar)).onClose(() -> {
        try {
          jar.close();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      });
    } else {
      throw new IOException(
          "Unsupported protocol for seed corpus resource directory: " + seedCorpusUrl);
    }
  }

  private static Stream<Map.Entry<String, byte[]>> walkSeedsInPath(Path path) throws IOException {
    // @ParameterTest automatically closes Streams and AutoCloseable instances.
    // noinspection resource
    return Files
        .find(path, Integer.MAX_VALUE,
            (fileOrDir, basicFileAttributes)
                -> !basicFileAttributes.isDirectory(),
            FileVisitOption.FOLLOW_LINKS)
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
