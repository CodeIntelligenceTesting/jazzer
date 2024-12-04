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

import static java.util.Arrays.stream;
import static java.util.Collections.newSetFromMap;
import static java.util.Collections.singletonList;
import static java.util.Collections.unmodifiableMap;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.code_intelligence.jazzer.utils.UnsafeProvider;
import com.code_intelligence.jazzer.utils.UnsafeUtils;
import java.io.File;
import java.io.IOException;
import java.lang.invoke.MethodType;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.jupiter.params.provider.Arguments;

class Utils {
  private static final Pattern DURATION_PATTERN =
      Pattern.compile("(?iu)([0-9]*) ?(ns|μs|ms|s|m|h|d)?");

  private static final Map<String, TimeUnit> DURATION_UNITS_LOOKUP;

  static {
    Map<String, TimeUnit> units = new HashMap<>();
    units.put("ns", TimeUnit.NANOSECONDS);
    units.put("μs", TimeUnit.MICROSECONDS);
    units.put("ms", TimeUnit.MILLISECONDS);
    units.put("s", TimeUnit.SECONDS);
    units.put("m", TimeUnit.MINUTES);
    units.put("h", TimeUnit.HOURS);
    units.put("d", TimeUnit.DAYS);
    DURATION_UNITS_LOOKUP = unmodifiableMap(units);
  }

  /**
   * Returns the resource path of the inputs directory for a given test class and method. The path
   * will have the form {@code <class name>Inputs/<method name>}
   */
  static String inputsDirectoryResourcePath(Class<?> testClass, Method testMethod) {
    return testClass.getSimpleName() + "Inputs" + "/" + testMethod.getName();
  }

  static String inputsDirectoryResourcePath(Class<?> testClass) {
    return testClass.getSimpleName() + "Inputs";
  }

  /**
   * Returns the file system path of the inputs corpus directory in the source tree, if it exists.
   * The directory is created if it does not exist, but the test resource directory itself exists.
   */
  static Optional<Path> inputsDirectorySourcePath(
      Class<?> testClass, Method testMethod, Path baseDir) {
    String inputsResourcePath = Utils.inputsDirectoryResourcePath(testClass, testMethod);
    // Make the inputs resource path absolute.
    if (!inputsResourcePath.startsWith("/")) {
      String inputsPackage = testClass.getPackage().getName().replace('.', '/');
      inputsResourcePath = "/" + inputsPackage + "/" + inputsResourcePath;
    }

    // Following the Maven directory layout, we look up the inputs directory under
    // src/test/resources. This should be correct also for multi-module projects as JUnit is usually
    // launched in the current module's root directory.
    Path testResourcesDirectory = baseDir.resolve("src").resolve("test").resolve("resources");
    Path sourceInputsDirectory = testResourcesDirectory;
    for (String segment : inputsResourcePath.split("/")) {
      sourceInputsDirectory = sourceInputsDirectory.resolve(segment);
    }
    if (Files.isDirectory(sourceInputsDirectory)) {
      return Optional.of(sourceInputsDirectory);
    }
    // If we can at least find the test resource directory, create the inputs directory.
    if (!Files.isDirectory(testResourcesDirectory)) {
      return Optional.empty();
    }
    try {
      return Optional.of(Files.createDirectories(sourceInputsDirectory));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  static Path generatedCorpusPath(Class<?> testClass, Method testMethod) {
    return Paths.get(".cifuzz-corpus", testClass.getName(), testMethod.getName());
  }

  /** Returns a heuristic default value for jazzer.instrument based on the test class. */
  static List<String> getLegacyInstrumentationFilter(Class<?> testClass) {
    // This is an extremely rough "implementation" of the public suffix list algorithm
    // (https://publicsuffix.org/): It tries to guess the shortest prefix of the package name that
    // isn't public. It doesn't use the actual list, but instead assumes that every root segment as
    // well as "com.github" are public. Examples:
    // - com.example.Test --> com.example.**
    // - com.example.foobar.Test --> com.example.**
    // - com.github.someones.repo.Test --> com.github.someones.**
    String packageName = testClass.getPackage().getName();
    String[] packageSegments = packageName.split("\\.");
    int numSegments = 2;
    if (packageSegments.length > 2
        && packageSegments[0].equals("com")
        && packageSegments[1].equals("github")) {
      numSegments = 3;
    }
    return singletonList(
        Stream.concat(Arrays.stream(packageSegments).limit(numSegments), Stream.of("**"))
            .collect(joining(".")));
  }

  private static final Pattern CLASSPATH_SPLITTER =
      Pattern.compile(Pattern.quote(File.pathSeparator));

  /**
   * Returns a heuristic default value for jazzer.instrument based on the files on the provided
   * classpath.
   */
  static Optional<List<String>> getClassPathBasedInstrumentationFilter(String classPath) {
    List<Path> includes =
        CLASSPATH_SPLITTER
            .splitAsStream(classPath)
            .map(Paths::get)
            // We consider classpath entries that are directories rather than jar files to contain
            // the classes of the current project rather than external dependencies. This is just a
            // heuristic and breaks with build systems that package all classes in jar files, e.g.
            // with Bazel.
            .filter(Files::isDirectory)
            .flatMap(
                root -> {
                  HashSet<Path> pkgs = new HashSet<>();
                  try {
                    Files.walkFileTree(
                        root,
                        new SimpleFileVisitor<Path>() {
                          @Override
                          public FileVisitResult preVisitDirectory(
                              Path dir, BasicFileAttributes basicFileAttributes)
                              throws IOException {
                            try (Stream<Path> entries = Files.list(dir)) {
                              // If a directory contains a .class file, we add an include filter
                              // matching it
                              // and all subdirectories.
                              // Special case: If there is a class defined at the root, only the
                              // unnamed
                              // package is included, so continue with the traversal of
                              // subdirectories
                              // to discover additional includes.
                              if (entries
                                  .filter(path -> path.toString().endsWith(".class"))
                                  .anyMatch(Files::isRegularFile)) {
                                Path pkgPath = root.relativize(dir);
                                pkgs.add(pkgPath);
                                if (pkgPath.toString().isEmpty()) {
                                  return FileVisitResult.CONTINUE;
                                } else {
                                  return FileVisitResult.SKIP_SUBTREE;
                                }
                              }
                            }
                            return FileVisitResult.CONTINUE;
                          }
                        });
                  } catch (IOException e) {
                    // This is only a best-effort heuristic anyway, ignore this directory.
                    return Stream.of();
                  }
                  return pkgs.stream();
                })
            .distinct()
            .collect(toList());
    if (includes.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(
        includes.stream()
            .map(Path::toString)
            // For classes without a package, only include the unnamed package.
            .map(path -> path.isEmpty() ? "*" : path.replace(File.separator, ".") + ".**")
            .sorted()
            .collect(toList()));
  }

  private static final Pattern COVERAGE_AGENT_ARG =
      Pattern.compile("-javaagent:.*(?:intellij-coverage-agent|jacoco).*");

  private static boolean isCoverageAgentPresent() {
    return ManagementFactory.getRuntimeMXBean().getInputArguments().stream()
        .anyMatch(s -> COVERAGE_AGENT_ARG.matcher(s).matches());
  }

  static boolean isGatheringCoverage() {
    return isCoverageAgentPresent() || permissivelyParseBoolean(System.getenv("JAZZER_COVERAGE"));
  }

  private static final boolean SET_FUZZING_ENV =
      System.getenv("JAZZER_FUZZ") != null || System.getProperty("JAZZER_FUZZ") != null;
  private static final boolean IS_FUZZING_ENV =
      permissivelyParseBoolean(System.getenv("JAZZER_FUZZ"))
          || permissivelyParseBoolean(System.getProperty("JAZZER_FUZZ"));

  /** Returns true if and only if the value is equal to "true", "1", or "yes" case-insensitively. */
  static boolean permissivelyParseBoolean(String value) {
    return value != null
        && (value.equalsIgnoreCase("true") || value.equals("1") || value.equalsIgnoreCase("yes"));
  }

  static boolean isFuzzing(ExtensionContext extensionContext) {
    return SET_FUZZING_ENV ? IS_FUZZING_ENV : runFromCommandLine(extensionContext);
  }

  static boolean runFromCommandLine(ExtensionContext extensionContext) {
    return extensionContext
        .getConfigurationParameter("jazzer.internal.command_line")
        .map(Boolean::parseBoolean)
        .orElse(false);
  }

  static List<String> getLibFuzzerArgs(ExtensionContext extensionContext) {
    List<String> args = new ArrayList<>();
    for (int i = 0; ; i++) {
      Optional<String> arg = extensionContext.getConfigurationParameter("jazzer.internal.arg." + i);
      if (!arg.isPresent()) {
        break;
      }
      args.add(arg.get());
    }
    return args;
  }

  static List<String> getCorpusFilesOrDirs(ExtensionContext context) {
    return getLibFuzzerArgs(context).stream()
        // Skip first parameter (executable name)
        .skip(1)
        .filter(arg -> !arg.startsWith("-"))
        .collect(toList());
  }

  /**
   * Convert the string to ISO 8601 (https://en.wikipedia.org/wiki/ISO_8601#Durations). We do not
   * allow for duration units longer than hours, so we can always prepend PT.
   */
  static long durationStringToSeconds(String duration) {
    if (duration.isEmpty()) {
      return 0;
    }
    String isoDuration =
        "PT" + duration.replace("sec", "s").replace("min", "m").replace("hr", "h").replace(" ", "");
    return Duration.parse(isoDuration).getSeconds();
  }

  static long parseJUnitTimeoutValueToSeconds(String value) {
    Matcher matcher = DURATION_PATTERN.matcher(value);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Failed to parse timeout duration string: " + value);
    }
    long count = Long.parseUnsignedLong(matcher.group(1));
    TimeUnit unit = DURATION_UNITS_LOOKUP.getOrDefault(matcher.group(2), TimeUnit.SECONDS);
    long seconds = unit.toSeconds(count);
    // libFuzzer's -timeout flag has seconds granularity. Every duration shorter than that is
    // rounded up to 1 second.
    return seconds != 0 ? seconds : 1;
  }

  /**
   * Creates {@link Arguments} for a single invocation of a parameterized test that can be
   * identified as having been created in this way by {@link #isMarkedInvocation}.
   *
   * @param displayName the display name to assign to every argument
   */
  static Arguments getMarkedArguments(Method method, String displayName) {
    return arguments(
        stream(method.getParameterTypes())
            .map(Utils::getMarkedInstance)
            // Wrap in named as toString may crash on marked instances.
            .map(arg -> named(displayName, arg))
            .toArray(Object[]::new));
  }

  /**
   * @return {@code true} if and only if the arguments for this test method invocation were created
   *     with {@link #getMarkedArguments}
   */
  static boolean isMarkedInvocation(ReflectiveInvocationContext<Method> invocationContext) {
    if (invocationContext.getArguments().stream().anyMatch(Utils::isMarkedInstance)) {
      if (invocationContext.getArguments().stream().allMatch(Utils::isMarkedInstance)) {
        return true;
      }
      throw new IllegalStateException(
          "Some, but not all arguments were marked in invocation of " + invocationContext);
    } else {
      return false;
    }
  }

  private static final ClassValue<Object> uniqueInstanceCache =
      new ClassValue<Object>() {
        @Override
        protected Object computeValue(Class<?> clazz) {
          return makeMarkedInstance(clazz);
        }
      };
  private static final Set<Object> uniqueInstances = newSetFromMap(new IdentityHashMap<>());

  // Visible for testing.
  static <T> T getMarkedInstance(Class<T> clazz) {
    // makeMarkedInstance creates new classes, which is expensive and can cause the JVM to run out
    // of metaspace. We thus cache the marked instances per class.
    Object instance = uniqueInstanceCache.get(clazz);
    uniqueInstances.add(instance);
    return (T) instance;
  }

  // Visible for testing.
  static boolean isMarkedInstance(Object instance) {
    return uniqueInstances.contains(instance);
  }

  private static Object makeMarkedInstance(Class<?> clazz) {
    if (clazz == Class.class) {
      return new Object() {}.getClass();
    }
    if (clazz.isArray()) {
      return Array.newInstance(clazz.getComponentType(), 0);
    }
    if (clazz.isInterface()) {
      return Proxy.newProxyInstance(
          Utils.class.getClassLoader(), new Class[] {clazz}, (o, method, objects) -> null);
    }

    if (clazz.isPrimitive()) {
      clazz = MethodType.methodType(clazz).wrap().returnType();
    } else if (Modifier.isAbstract(clazz.getModifiers())) {
      clazz = UnsafeUtils.defineAnonymousConcreteSubclass(clazz);
    }

    try {
      return clazz.cast(UnsafeProvider.getUnsafe().allocateInstance(clazz));
    } catch (InstantiationException e) {
      throw new IllegalStateException(e);
    }
  }

  public static boolean isWindows() {
    return System.getProperty("os.name").toLowerCase().contains("win");
  }
}
