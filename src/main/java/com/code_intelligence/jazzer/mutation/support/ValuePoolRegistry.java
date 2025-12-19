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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;

import com.code_intelligence.jazzer.mutation.annotation.ValuePool;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ValuePoolRegistry {
  private final Method fuzzTestMethod;
  private final Path baseDir;
  private final Map<String, Supplier<Stream<?>>> pools;
  private final Map<Path, Optional<byte[]>> pathToBytesCache = new LinkedHashMap<>();

  public ValuePoolRegistry(Method fuzzTestMethod) {
    this(fuzzTestMethod, computeBaseDir());
  }

  protected ValuePoolRegistry(Method fuzzTestMethod, Path baseDir) {
    this.fuzzTestMethod = fuzzTestMethod;
    this.pools = extractValueSuppliers(fuzzTestMethod);
    this.baseDir = baseDir;
  }

  private static Path computeBaseDir() {
    return System.getProperty("jazzer.internal.basedir") == null
        ? Paths.get("").toAbsolutePath().normalize()
        : Paths.get(System.getProperty("jazzer.internal.basedir"));
  }

  /**
   * Extract probability of the very first {@code ValuePool} annotation on the given type. The
   * {@code @ValuePool} annotation directly on the type is preferred; if there is none, the first
   * one appended because of {@code PropertyConstraint.RECURSIVE} is used. Any further
   * {@code @ValuePool} annotations appended later to this type because of {@code
   * PropertyConstraint.RECURSIVE}, are ignored. Callers should ensure that at least one
   * {@code @ValuePool} annotation is present on the type.
   */
  public double extractFirstProbability(AnnotatedType type) {
    // If there are several @ValuePool annotations on the type, this will take the most
    // immediate one, because @ValuePool is not repeatable.
    ValuePool[] valuePoolAnnotations = type.getAnnotationsByType(ValuePool.class);
    if (valuePoolAnnotations.length == 0) {
      // If we are here, it's a bug in the caller.
      throw new IllegalStateException("Expected to find @ValuePool, but found none.");
    }
    double p = valuePoolAnnotations[0].p();
    require(p >= 0.0 && p <= 1.0, "@ValuePool p must be in [0.0, 1.0], but was " + p);
    return p;
  }

  public Stream<?> extractUserValues(AnnotatedType type) {
    Stream<?> valuesFromSourceMethods =
        getValuePoolAnnotations(type).stream()
            .map(ValuePool::value)
            .flatMap(Arrays::stream)
            .filter(name -> !name.isEmpty())
            .flatMap(
                name -> {
                  Supplier<Stream<?>> supplier = pools.get(name);
                  if (supplier == null) {
                    throw new IllegalStateException(
                        "@ValuePool: No method named '"
                            + name
                            + "' found for type "
                            + type.getType().getTypeName()
                            + " in fuzz test method "
                            + fuzzTestMethod.getName()
                            + ". Available provider methods: "
                            + String.join(", ", pools.keySet()));
                  }
                  return supplier.get();
                })
            .distinct();

    // Walking the file system only makes sense for ValuePool's that annotate byte[] types.
    if (type.getType() == byte[].class) {
      return Stream.concat(valuesFromSourceMethods, extractByteArraysFromPatterns(type));
    } else {
      return valuesFromSourceMethods;
    }
  }

  private Stream<byte[]> extractByteArraysFromPatterns(AnnotatedType type) {
    List<ValuePool> annotations = getValuePoolAnnotations(type);

    return annotations.stream()
        .map(ValuePool::files)
        .flatMap(Arrays::stream)
        .filter(glob -> !glob.isEmpty())
        .distinct()
        .flatMap(
            glob -> {
              List<Path> paths = GlobUtils.collectPathsForGlob(baseDir, glob);
              if (paths.isEmpty()) {
                throw new IllegalArgumentException(
                    "@ValuePool: No files matched glob pattern '"
                        + glob
                        + "' for type "
                        + type.getType().getTypeName()
                        + " in fuzz test method "
                        + fuzzTestMethod.getName()
                        + ".");
              }
              return paths.stream();
            })
        .distinct()
        .map(this::tryReadFile)
        .filter(Optional::isPresent)
        .map(Optional::get);
  }

  private List<ValuePool> getValuePoolAnnotations(AnnotatedType type) {
    return Arrays.stream(type.getAnnotations())
        .filter(annotation -> annotation instanceof ValuePool)
        .map(annotation -> (ValuePool) annotation)
        .collect(Collectors.toList());
  }

  private Optional<byte[]> tryReadFile(Path path) {
    Path normalizedPath = path.toAbsolutePath().normalize();
    return pathToBytesCache.computeIfAbsent(
        normalizedPath,
        p -> {
          try {
            return Optional.of(Files.readAllBytes(p));
          } catch (IOException e) {
            return Optional.empty();
          }
        });
  }

  private static Map<String, Supplier<Stream<?>>> extractValueSuppliers(Method fuzzTestMethod) {
    return Arrays.stream(fuzzTestMethod.getDeclaringClass().getDeclaredMethods())
        .filter(m -> m.getParameterCount() == 0)
        .filter(m -> Stream.class.equals(m.getReturnType()))
        .filter(m -> Modifier.isStatic(m.getModifiers()))
        .collect(Collectors.toMap(Method::getName, ValuePoolRegistry::createLazyStreamSupplier));
  }

  private static Supplier<Stream<?>> createLazyStreamSupplier(Method method) {
    return new Supplier<Stream<?>>() {
      private volatile List<Object> cachedData = null;

      @Override
      public Stream<?> get() {
        if (cachedData == null) {
          synchronized (this) {
            if (cachedData == null) {
              cachedData = loadDataFromMethod(method);
            }
          }
          if (cachedData.isEmpty()) {
            throw new IllegalStateException(
                "@ValuePool: method '"
                    + method.getName()
                    + "' returned no values. Value pool methods must return at least one value.");
          }
        }
        return cachedData.stream();
      }
    };
  }

  private static List<Object> loadDataFromMethod(Method method) {
    method.setAccessible(true);
    try {
      Stream<?> stream = (Stream<?>) method.invoke(null);
      return stream.collect(Collectors.toList());
    } catch (IllegalAccessException e) {
      throw new RuntimeException("@ValuePool: Access denied for method " + method.getName(), e);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      throw new RuntimeException(
          "@ValuePool: Method " + method.getName() + " threw an exception",
          cause != null ? cause : e);
    }
  }
}
