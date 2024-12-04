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

package com.code_intelligence.jazzer.driver.junit;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;
import static org.junit.platform.launcher.EngineFilter.includeEngines;
import static org.junit.platform.launcher.TagFilter.includeTags;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarFile;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.platform.engine.DiscoverySelector;
import org.junit.platform.engine.UniqueId.Segment;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

/**
 * Scans the classpath for fuzz tests and emits one line per test with its identifier in the form
 * {@code com.example.MyFuzzTest} or {@code com.example.MyTests::fuzzTest}.
 *
 * <p>If no class names are provided, all directories (but not JAR files) on the classpath are
 * scanned for tests. If one or more class name is provided, only these classes are scanned.
 *
 * <p>The tool assumes that JUnit is on the classpath and only looks for {@link
 * com.code_intelligence.jazzer.junit.FuzzTest}s and does not support {@code fuzzerTestOneInput}
 * functions.
 */
public final class FuzzTestLister {

  private static final Pattern CLASSPATH_SPLITTER =
      Pattern.compile(Pattern.quote(File.pathSeparator));

  // @FuzzTest unique IDs are expected to be of the form:
  // [engine:junit-jupiter]/[class:com.example.MyTests]/[test-template:myFuzzTest(com.code_intelligence.jazzer.api.FuzzedDataProvider)]
  private static final List<String> EXPECTED_SEGMENT_TYPES =
      unmodifiableList(asList("engine", "class", "test-template"));

  private static final Pattern MANIFEST_PATH_SPLITTER = Pattern.compile(Pattern.quote(" "));

  public static List<String> listFuzzTests(List<String> classes) {
    // JUnit does not report errors if class files could not be loaded successfully, rather it just
    // logs an appropriate message and continues.
    // The application is expected to be closed after listing fuzz tests, hence it's fine to change
    // logger settings globally.
    if (System.getenv("JAZZER_DEBUG") != null) {
      Logger logger = Logger.getLogger("org.junit");
      logger.setLevel(Level.FINE);
      ConsoleHandler consoleHandler = new ConsoleHandler();
      consoleHandler.setLevel(Level.FINE);
      logger.addHandler(consoleHandler);
    }

    LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request()
            .selectors(selectorsFor(classes))
            .filters(
                includeEngines("junit-jupiter"),
                // All @FuzzTests are annotated with this tag.
                includeTags("jazzer"))
            .build();
    TestPlan testPlan = LauncherFactory.create().discover(request);
    return testPlan
        // Test engine level
        .getRoots()
        .stream()
        // Test class level
        .flatMap(engineTestIdentifier -> testPlan.getDescendants(engineTestIdentifier).stream())
        // Test method level
        .flatMap(classTestIdentifier -> testPlan.getDescendants(classTestIdentifier).stream())
        .map(FuzzTestLister::toMethodReference)
        .filter(Optional::isPresent)
        .map(Optional::get)
        .sorted()
        // Jazzer only runs a single fuzz test per method name, the one that comes first in
        // JUnit execution order.
        // TODO: Clarify whether it would be better to error out in case of duplicates. Whereas
        //       the fuzz tests that aren't executed during a JUnit test run are clearly marked
        //       as skipped, this may be less visible during a remote run.
        .distinct()
        .collect(toList());
  }

  private static List<? extends DiscoverySelector> selectorsFor(List<String> classes) {
    if (classes.isEmpty()) {
      return DiscoverySelectors.selectClasspathRoots(
          CLASSPATH_SPLITTER
              .splitAsStream(System.getProperty("java.class.path"))
              .map(Paths::get)
              .flatMap(
                  path ->
                      isCifuzzClasspathCompressionJar(path)
                          ? extractClasspathFromCifuzzManifest(path)
                          : Stream.of(path))
              // Only scan directories, not .jar files, as with Maven and Gradle the project's own
              // classes are typically contained in a directory, and we do not want to scan
              // third-party dependencies for fuzz tests.
              .filter(Files::isDirectory)
              .collect(Collectors.toSet()));
    }
    return classes.stream().map(DiscoverySelectors::selectClass).collect(toList());
  }

  private static Optional<String> toMethodReference(TestIdentifier testIdentifier) {
    List<Segment> segments = testIdentifier.getUniqueIdObject().getSegments();
    if (!segments.stream().map(Segment::getType).collect(toList()).equals(EXPECTED_SEGMENT_TYPES)) {
      return Optional.empty();
    }
    String className = segments.get(1).getValue();
    String methodNameAndArgs = segments.get(2).getValue();
    String methodName = methodNameAndArgs.substring(0, methodNameAndArgs.indexOf('('));
    return Optional.of(String.format("%s::%s", className, methodName));
  }

  private static boolean isCifuzzClasspathCompressionJar(Path jarPath) {
    return jarPath.toString().contains("cifuzz-classpath-compression")
        && jarPath.toString().endsWith("manifest.jar");
  }

  private static Stream<Path> extractClasspathFromCifuzzManifest(Path path) {
    try (JarFile jarFile = new JarFile(path.toFile())) {
      String jarClassPath = jarFile.getManifest().getMainAttributes().getValue("Class-Path");
      // Extract "Class-Path" entries from the manifest of the path compressing JAR file and
      // add them to the classpath.
      return jarClassPathToPaths(jarClassPath, path);
    } catch (IOException | NullPointerException e) {
      throw new RuntimeException(
          "Failed to extract class path from path-compressing manifest: " + path, e);
    }
  }

  public static Stream<Path> jarClassPathToPaths(String jarClassPath, Path jarPath) {
    return MANIFEST_PATH_SPLITTER
        .splitAsStream(jarClassPath)
        // These are valid JAR paths on Windows: \C:\path\to\file.jar, /C:/path/to/file.jar
        // We need to remove the leading (back-)slash to make a valid Path.
        .map(p -> p.matches("^[\\\\/][A-Za-z]:.*") ? p.substring(1) : p)
        .map(Paths::get)
        .map(p -> jarPath.getParent().resolve(p).normalize())
        .collect(Collectors.toSet())
        .stream();
  }

  private FuzzTestLister() {}
}
