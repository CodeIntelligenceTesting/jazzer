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

import com.code_intelligence.jazzer.agent.AgentInstaller;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.AnnotationConsumer;

class FuzzTestArgumentsProvider implements ArgumentsProvider, AnnotationConsumer<FuzzTest> {
  private static final String INCORRECT_PARAMETERS_MESSAGE =
      "Methods annotated with @FuzzTest must take at least one parameter";
  private static final AtomicBoolean agentInstalled = new AtomicBoolean(false);

  private FuzzTest annotation;

  @Override
  public void accept(FuzzTest annotation) {
    this.annotation = annotation;
  }

  private void configureAndInstallAgent(ExtensionContext extensionContext) throws IOException {
    if (!agentInstalled.compareAndSet(false, true)) {
      return;
    }
    if (Utils.isFuzzing(extensionContext)) {
      FuzzTestExecutor executor =
          FuzzTestExecutor.prepare(extensionContext, annotation.maxDuration());
      extensionContext.getStore(Namespace.GLOBAL).put(FuzzTestExecutor.class, executor);
      AgentConfigurator.forFuzzing(extensionContext);
    } else {
      AgentConfigurator.forRegressionTest(extensionContext);
    }
    AgentInstaller.install(Opt.hooks);
  }

  @Override
  public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext)
      throws IOException {
    // FIXME(fmeum): Calling this here feels like a hack. There should be a lifecycle hook that runs
    //  before the argument discovery for a ParameterizedTest is kicked off, but I haven't found
    //  one.
    configureAndInstallAgent(extensionContext);
    Stream<Map.Entry<String, byte[]>> rawSeeds;
    if (Utils.isFuzzing(extensionContext)) {
      // When fuzzing, supply a single set of arguments to trigger an invocation of the test method.
      // An InvocationInterceptor is used to skip the actual invocation and instead start the
      // fuzzer.
      rawSeeds = Stream.of(new SimpleEntry<>("Fuzzing...", new byte[] {}));
    } else {
      rawSeeds = Stream.of(new SimpleEntry<>("<empty input>", new byte[] {}));
      Class<?> testClass = extensionContext.getRequiredTestClass();
      rawSeeds = Stream.concat(rawSeeds, walkInputs(testClass));
      if (Utils.isCoverageAgentPresent()
          && Files.isDirectory(Utils.generatedCorpusPath(testClass))) {
        rawSeeds = Stream.concat(rawSeeds, walkInputsInPath(Utils.generatedCorpusPath(testClass)));
      }
    }
    return adaptInputsForFuzzTest(extensionContext.getRequiredTestMethod(), rawSeeds)
        .onClose(() -> {
          if (!Utils.isFuzzing(extensionContext)) {
            extensionContext.publishReportEntry(
                "No fuzzing has been performed, the fuzz test has only been executed on the fixed "
                + "set of inputs in the seed corpus.\n"
                + "To start fuzzing, run a test with the environment variable JAZZER_FUZZ set to a "
                + "non-empty value.");
          }
        });
  }

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
          mutator.read(new ByteArrayInputStream(e.getValue()));
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

  private Stream<Map.Entry<String, byte[]>> walkInputs(Class<?> testClass) throws IOException {
    URL inputsDirUrl = testClass.getResource(Utils.inputsDirectoryResourcePath(testClass));
    if (inputsDirUrl == null) {
      return Stream.empty();
    }
    URI inputsDirUri;
    try {
      inputsDirUri = inputsDirUrl.toURI();
    } catch (URISyntaxException e) {
      throw new IOException("Failed to open inputs resource directory: " + inputsDirUrl, e);
    }
    if (inputsDirUri.getScheme().equals("file")) {
      // The test is executed from class files, which usually happens when run from inside an IDE.
      return walkInputsInPath(Paths.get(inputsDirUri));
    } else if (inputsDirUri.getScheme().equals("jar")) {
      FileSystem jar = FileSystems.newFileSystem(inputsDirUri, new HashMap<>());
      // inputsDirUrl looks like this:
      // file:/tmp/testdata/ExampleFuzzTest_deploy.jar!/com/code_intelligence/jazzer/junit/testdata/ExampleFuzzTestInputs
      String pathInJar = inputsDirUrl.getFile().substring(inputsDirUrl.getFile().indexOf('!') + 1);
      return walkInputsInPath(jar.getPath(pathInJar)).onClose(() -> {
        try {
          jar.close();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      });
    } else {
      throw new IOException("Unsupported protocol for inputs resource directory: " + inputsDirUrl);
    }
  }

  private static Stream<Map.Entry<String, byte[]>> walkInputsInPath(Path path) throws IOException {
    // @ParameterTest automatically closes Streams and AutoCloseable instances.
    // noinspection resource
    return Files
        .find(path, Integer.MAX_VALUE,
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
