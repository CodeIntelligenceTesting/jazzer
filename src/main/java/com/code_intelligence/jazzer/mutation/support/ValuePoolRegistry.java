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
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ValuePoolRegistry {
  private final Method fuzzTestMethod;
  private final Path baseDir;
  private final Map<Method, List<?>> supplierValuesCache = new LinkedHashMap<>();
  private final Map<Path, Optional<byte[]>> pathToBytesCache = new LinkedHashMap<>();

  public ValuePoolRegistry(Method fuzzTestMethod) {
    this(fuzzTestMethod, computeBaseDir());
  }

  protected ValuePoolRegistry(Method fuzzTestMethod, Path baseDir) {
    this.fuzzTestMethod = fuzzTestMethod;
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

  public int extractFirstMaxMutations(AnnotatedType type) {
    ValuePool[] valuePoolAnnotations = type.getAnnotationsByType(ValuePool.class);
    if (valuePoolAnnotations.length == 0) {
      // If we are here, it's a bug in the caller.
      throw new IllegalStateException("Expected to find @ValuePool, but found none.");
    }
    int maxMutations = valuePoolAnnotations[0].maxMutations();
    require(maxMutations >= 0, "@ValuePool maxMutations must be >= 0, but was " + maxMutations);
    return maxMutations;
  }

  public Stream<?> extractUserValues(AnnotatedType type) {
    Stream<?> valuesFromSourceMethods =
        getValuePoolAnnotations(type).stream()
            .map(ValuePool::value)
            .flatMap(Arrays::stream)
            .filter(name -> !name.isEmpty())
            .map(String::trim)
            .flatMap(this::loadUserValuesFromSupplier)
            .distinct();

    // Walking the file system only makes sense for pools that annotate byte[] types.
    if (type.getType() == byte[].class) {
      return Stream.concat(valuesFromSourceMethods, extractByteArraysFromPatterns(type));
    } else {
      return valuesFromSourceMethods;
    }
  }

  private Stream<?> loadUserValuesFromSupplier(String supplierRef) {
    Method supplier = resolveSupplier(supplierRef);
    return supplierValuesCache
        .computeIfAbsent(supplier, s -> loadValuesFromMethod(s, supplierRef))
        .stream();
  }

  private Method resolveSupplier(String supplierRef) {
    if (supplierRef.isEmpty()) {
      throw new IllegalArgumentException("@ValuePool: Supplier method cannot be blank");
    }

    int hashIndex = supplierRef.indexOf('#');

    // Supplier method is in the fuzz test class
    if (hashIndex == -1) {
      return resolveSupplier(fuzzTestMethod.getDeclaringClass(), supplierRef);
    }

    // Supplier method is not in the fuzz test class
    // Validate the format of the supplier reference before loading the class
    if (hashIndex != supplierRef.lastIndexOf('#')) {
      throw new IllegalArgumentException(
          "@ValuePool: Invalid supplier method reference (multiple '#'): " + supplierRef);
    }
    if (hashIndex == 0 || hashIndex == supplierRef.length() - 1) {
      throw new IllegalArgumentException(
          "@ValuePool: Invalid supplier method reference (expected 'ClassName#methodName'): "
              + supplierRef);
    }

    String className = supplierRef.substring(0, hashIndex);
    String methodName = supplierRef.substring(hashIndex + 1);
    if (className.isEmpty() || methodName.isEmpty()) {
      throw new IllegalArgumentException(
          "@ValuePool: Invalid supplier method reference (expected 'ClassName#methodName'): "
              + supplierRef);
    }

    Class<?> clazz = loadClass(className);
    return resolveSupplier(clazz, methodName);
  }

  private Method resolveSupplier(Class<?> clazz, String methodName) {
    try {
      return clazz.getDeclaredMethod(methodName);
    } catch (NoSuchMethodException e) {
      throw new IllegalArgumentException(
          "@ValuePool: No supplier method named '" + methodName + "' found in class " + clazz, e);
    }
  }

  private Class<?> loadClass(String className) {
    ClassLoader fuzzTestLoader = fuzzTestMethod.getDeclaringClass().getClassLoader();
    try {
      return Class.forName(className, false, fuzzTestLoader);
    } catch (ClassNotFoundException | LinkageError | SecurityException firstFailure) {
      // Retry with the context class loader
      ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
      if (contextLoader != null && contextLoader != fuzzTestLoader) {
        try {
          return Class.forName(className, false, contextLoader);
        } catch (ClassNotFoundException | LinkageError | SecurityException secondFailure) {
          IllegalArgumentException ex =
              new IllegalArgumentException(
                  "@ValuePool: Failed to load class '"
                      + className
                      + "' (fuzzTestLoader="
                      + fuzzTestLoader
                      + ", contextLoader="
                      + contextLoader
                      + ")",
                  firstFailure);
          ex.addSuppressed(secondFailure);
          throw ex;
        }
      }
      if (firstFailure instanceof ClassNotFoundException) {
        throw new IllegalArgumentException(
            "@ValuePool: No class named '" + className + "' found", firstFailure);
      }
      throw new IllegalArgumentException(
          "@ValuePool: Failed to load class '"
              + className
              + "' using class loader "
              + fuzzTestLoader,
          firstFailure);
    }
  }

  private List<Object> loadValuesFromMethod(Method supplier, String supplierRef) {
    if (!Modifier.isStatic(supplier.getModifiers())) {
      throw new IllegalStateException(
          "@ValuePool: supplier method '"
              + supplierRef
              + "' must be static in fuzz test method "
              + fuzzTestMethod.getName());
    }
    if (!Stream.class.equals(supplier.getReturnType())) {
      throw new IllegalStateException(
          "@ValuePool: supplier method '"
              + supplierRef
              + "' must return a Stream<?> in fuzz test method "
              + fuzzTestMethod.getName());
    }

    supplier.setAccessible(true);

    try {
      List<Object> values = ((Stream<?>) supplier.invoke(null)).collect(Collectors.toList());
      if (values.isEmpty()) {
        throw new IllegalStateException(
            "@ValuePool: supplier method '" + supplierRef + "' returned no values.");
      }
      return values;
    } catch (IllegalAccessException e) {
      throw new RuntimeException("@ValuePool: Access denied for supplier method " + supplierRef, e);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      throw new RuntimeException(
          "@ValuePool: Supplier method " + supplierRef + " threw an exception",
          cause != null ? cause : e);
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
}
