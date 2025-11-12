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
import static java.util.Arrays.stream;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.AnnotatedWildcardType;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.stream.IntStream;

/**
 * Utilities for resolving {@link AnnotatedType} trees that contain references to the type variables
 * of a parameterized class.
 *
 * <p>The Java reflection API exposes mutator targets as {@link AnnotatedType}s. When the target
 * instantiates a generic class such as {@code MyBean<String>}, the bean's fields and accessors may
 * still refer to the type variable {@code T}. The helper provided here walks those annotated type
 * trees, replaces occurrences of the class' type variables with the concrete annotated arguments
 * from the instantiation, and synthesizes fresh {@link AnnotatedType}s that retain annotations and
 * nested generic structure.
 */
public class ParameterizedTypeSupport {
  /**
   * Replaces type variables in {@code type} with the annotated concrete type arguments from {@code
   * classType}.
   *
   * <p>For example, given {@code class Box<T> { List<T> values; }} and the annotated type {@code
   * Box<@NotNull String>}, calling this method with the {@code values} field's annotated type
   * returns a new {@link AnnotatedType} representing {@code List<@NotNull String>}.
   *
   * @param clazz the generic class that declares the type variables
   * @param classType the annotated instantiation of {@code clazz}
   * @param type the annotated type to resolve (e.g. a constructor parameter or getter return type)
   */
  public static AnnotatedType resolveTypeArguments(
      Class<?> clazz, AnnotatedType classType, AnnotatedType type) {
    if (!(classType instanceof AnnotatedParameterizedType)) {
      return type;
    }

    TypeVariable<?>[] typeParameters = clazz.getTypeParameters();
    AnnotatedType[] typeArguments =
        ((AnnotatedParameterizedType) classType).getAnnotatedActualTypeArguments();

    require(typeArguments.length == typeParameters.length);

    Map<TypeVariable<?>, AnnotatedType> mapping = new HashMap<>();
    for (int i = 0; i < typeParameters.length; i++) {
      mapping.put(typeParameters[i], typeArguments[i]);
    }
    return resolveRecursive(type.getType(), type, mapping);
  }

  /**
   * Resolves {@code annotated} according to the substitutions provided in {@code mapping}. The
   * method recreates wrapper objects for parameterized, array, and wildcard types so that their
   * nested type variables are resolved as well.
   */
  private static AnnotatedType resolveRecursive(
      Type type, AnnotatedType annotated, Map<TypeVariable<?>, AnnotatedType> mapping) {
    if (type instanceof ParameterizedType) {
      // E.g. `List<T>`
      require(annotated instanceof AnnotatedParameterizedType);
      return resolveParameterizedType(
          (ParameterizedType) type, (AnnotatedParameterizedType) annotated, mapping);
    } else if (type instanceof GenericArrayType) {
      // E.g. `T[]`
      require(annotated instanceof AnnotatedArrayType);
      return resolveArrayType((GenericArrayType) type, (AnnotatedArrayType) annotated, mapping);
    } else if (type instanceof WildcardType) {
      // E.g. `? extends T`
      require(annotated instanceof AnnotatedWildcardType);
      return resolveWildcardType((AnnotatedWildcardType) annotated, mapping);
    } else if (type instanceof TypeVariable) {
      // E.g. `T`
      AnnotatedType replacement = mapping.get(type);
      if (replacement == null) {
        return annotated;
      }
      return TypeSupport.forwardAnnotations(annotated, replacement);
    }
    return annotated;
  }

  private static AnnotatedParameterizedType resolveParameterizedType(
      ParameterizedType type,
      AnnotatedParameterizedType annotated,
      Map<TypeVariable<?>, AnnotatedType> mapping) {
    AnnotatedType[] annotatedArgs = annotated.getAnnotatedActualTypeArguments();
    Type[] typeArgs = type.getActualTypeArguments();
    AnnotatedType[] resolvedArgs =
        IntStream.range(0, annotatedArgs.length)
            .mapToObj(i -> resolveRecursive(typeArgs[i], annotatedArgs[i], mapping))
            .toArray(AnnotatedType[]::new);
    Type resolvedType =
        new ParameterizedTypeWrapper(
            type.getRawType(),
            stream(resolvedArgs).map(AnnotatedType::getType).toArray(Type[]::new),
            type.getOwnerType());
    return new AnnotatedParameterizedTypeWrapper(annotated, resolvedType, resolvedArgs);
  }

  private static AnnotatedArrayType resolveArrayType(
      GenericArrayType type,
      AnnotatedArrayType annotated,
      Map<TypeVariable<?>, AnnotatedType> mapping) {
    AnnotatedType resolved =
        resolveRecursive(
            type.getGenericComponentType(), annotated.getAnnotatedGenericComponentType(), mapping);
    Type resolvedType = new GenericArrayTypeWrapper(resolved.getType());
    return new AnnotatedArrayTypeWrapper(annotated, resolvedType, resolved);
  }

  private static AnnotatedWildcardType resolveWildcardType(
      AnnotatedWildcardType annotated, Map<TypeVariable<?>, AnnotatedType> mapping) {
    AnnotatedType[] resolvedLower =
        stream(annotated.getAnnotatedLowerBounds())
            .map(t -> resolveRecursive(t.getType(), t, mapping))
            .toArray(AnnotatedType[]::new);
    AnnotatedType[] resolvedUpper =
        stream(annotated.getAnnotatedUpperBounds())
            .map(t -> resolveRecursive(t.getType(), t, mapping))
            .toArray(AnnotatedType[]::new);
    Type resolvedType =
        new WildcardTypeWrapper(
            stream(resolvedLower).map(AnnotatedType::getType).toArray(Type[]::new),
            stream(resolvedUpper).map(AnnotatedType::getType).toArray(Type[]::new));
    return new AnnotatedWildcardTypeWrapper(annotated, resolvedType, resolvedLower, resolvedUpper);
  }

  private static class WildcardTypeWrapper implements WildcardType {
    private final Type[] lowerBounds;
    private final Type[] upperBounds;

    public WildcardTypeWrapper(Type[] lowerBounds, Type[] upperBounds) {
      this.lowerBounds = lowerBounds.clone();
      this.upperBounds = upperBounds.clone();
    }

    @Override
    public Type[] getUpperBounds() {
      return upperBounds.clone();
    }

    @Override
    public Type[] getLowerBounds() {
      return lowerBounds.clone();
    }

    @Override
    public String toString() {
      Type[] lowerBounds = getLowerBounds();
      Type[] bounds = lowerBounds;
      StringBuilder sb = new StringBuilder();

      if (lowerBounds.length > 0) sb.append("? super ");
      else {
        Type[] upperBounds = getUpperBounds();
        if (upperBounds.length > 0 && !upperBounds[0].equals(Object.class)) {
          bounds = upperBounds;
          sb.append("? extends ");
        } else return "?";
      }

      StringJoiner sj = new StringJoiner(" & ");
      for (Type bound : bounds) {
        sj.add(bound.getTypeName());
      }
      sb.append(sj);

      return sb.toString();
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof WildcardType)) {
        return false;
      }
      WildcardType that = (WildcardType) other;
      return Arrays.equals(getLowerBounds(), that.getLowerBounds())
          && Arrays.equals(getUpperBounds(), that.getUpperBounds());
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(getLowerBounds()) * 31 + Arrays.hashCode(getUpperBounds());
    }
  }

  private static class GenericArrayTypeWrapper implements GenericArrayType {

    private final Type componentType;

    public GenericArrayTypeWrapper(Type componentType) {
      this.componentType = componentType;
    }

    @Override
    public Type getGenericComponentType() {
      return componentType;
    }

    @Override
    public String toString() {
      return componentType.getTypeName() + "[]";
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof GenericArrayType)) {
        return false;
      }
      GenericArrayType that = (GenericArrayType) other;
      return componentType.equals(that.getGenericComponentType());
    }

    @Override
    public int hashCode() {
      return componentType.hashCode();
    }
  }

  private static class ParameterizedTypeWrapper implements ParameterizedType {
    private final Type rawType;
    private final Type[] typeArguments;
    private final Type ownerType;

    public ParameterizedTypeWrapper(Type rawType, Type[] typeArguments, Type ownerType) {
      this.rawType = rawType;
      this.typeArguments = typeArguments.clone();
      this.ownerType = ownerType;
    }

    @Override
    public Type[] getActualTypeArguments() {
      return typeArguments.clone();
    }

    @Override
    public Type getRawType() {
      return rawType;
    }

    @Override
    public Type getOwnerType() {
      return ownerType;
    }

    @Override
    public String toString() {
      return rawType.getTypeName()
          + "<"
          + Arrays.stream(typeArguments)
              .map(Type::getTypeName)
              .reduce((a, b) -> a + "," + b)
              .orElse("")
          + ">";
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof ParameterizedType)) {
        return false;
      }
      ParameterizedType that = (ParameterizedType) other;
      return Objects.equals(getRawType(), that.getRawType())
          && Objects.equals(getOwnerType(), that.getOwnerType())
          && Arrays.equals(getActualTypeArguments(), that.getActualTypeArguments());
    }

    @Override
    public int hashCode() {
      return Objects.hash(getRawType(), getOwnerType(), Arrays.hashCode(getActualTypeArguments()));
    }
  }

  private static class AnnotatedTypeWrapper implements AnnotatedType {
    final AnnotatedType annotatedType;
    private final Type type;

    AnnotatedTypeWrapper(AnnotatedType annotatedType, Type type) {
      this.annotatedType = annotatedType;
      this.type = type;
    }

    @Override
    public Type getType() {
      return type;
    }

    @Override
    public <T extends Annotation> T getAnnotation(Class<T> annotationClass) {
      return annotatedType.getAnnotation(annotationClass);
    }

    @Override
    public Annotation[] getAnnotations() {
      return annotatedType.getAnnotations();
    }

    @Override
    public Annotation[] getDeclaredAnnotations() {
      return annotatedType.getDeclaredAnnotations();
    }

    public AnnotatedType getAnnotatedOwnerType() {
      return getAnnotatedOwnerTypeOrNull(annotatedType);
    }

    @Override
    public String toString() {
      // TODO: include annotations in string
      return type.toString();
    }

    protected boolean equalsTypeAndAnnotations(AnnotatedType that) {
      return getType().equals(that.getType())
          // Treat ordering of annotations as significant
          && Arrays.equals(getAnnotations(), that.getAnnotations())
          && Objects.equals(getAnnotatedOwnerType(), getAnnotatedOwnerTypeOrNull(that));
    }

    int baseHashCode() {
      return type.hashCode()
          ^
          // Acceptable to use Objects.hash rather than
          // Arrays.deepHashCode since the elements of the array
          // are not themselves arrays.
          Objects.hash((Object[]) getAnnotations())
          ^ Objects.hash(getAnnotatedOwnerType());
    }
  }

  private static class AnnotatedWildcardTypeWrapper extends AnnotatedTypeWrapper
      implements AnnotatedWildcardType {
    private final AnnotatedType[] upperBounds;
    private final AnnotatedType[] lowerBounds;

    AnnotatedWildcardTypeWrapper(
        AnnotatedType annotatedType,
        Type type,
        AnnotatedType[] lowerBounds,
        AnnotatedType[] upperBounds) {
      super(annotatedType, type);
      this.upperBounds = upperBounds.clone();
      this.lowerBounds = lowerBounds.clone();
    }

    @Override
    public AnnotatedType[] getAnnotatedLowerBounds() {
      return lowerBounds.clone();
    }

    @Override
    public AnnotatedType[] getAnnotatedUpperBounds() {
      return upperBounds.clone();
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof AnnotatedWildcardType)) {
        return false;
      }
      AnnotatedWildcardType that = (AnnotatedWildcardType) o;
      return equalsTypeAndAnnotations(that)
          && Arrays.equals(getAnnotatedLowerBounds(), that.getAnnotatedLowerBounds())
          && Arrays.equals(getAnnotatedUpperBounds(), that.getAnnotatedUpperBounds());
    }

    @Override
    public int hashCode() {
      return baseHashCode()
          ^ Objects.hash((Object[]) getAnnotatedLowerBounds())
          ^ Objects.hash((Object[]) getAnnotatedUpperBounds());
    }
  }

  private static class AnnotatedArrayTypeWrapper extends AnnotatedTypeWrapper
      implements AnnotatedArrayType {

    private final AnnotatedType componentType;

    AnnotatedArrayTypeWrapper(AnnotatedType annotatedType, Type type, AnnotatedType componentType) {
      super(annotatedType, type);
      this.componentType = componentType;
    }

    @Override
    public AnnotatedType getAnnotatedGenericComponentType() {
      return componentType;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof AnnotatedArrayType)) {
        return false;
      }
      AnnotatedArrayType that = (AnnotatedArrayType) o;
      return equalsTypeAndAnnotations(that)
          && componentType.equals(that.getAnnotatedGenericComponentType());
    }

    @Override
    public int hashCode() {
      return baseHashCode() ^ Objects.hash(componentType);
    }
  }

  private static class AnnotatedParameterizedTypeWrapper extends AnnotatedTypeWrapper
      implements AnnotatedParameterizedType {
    private final AnnotatedType[] typeArguments;

    AnnotatedParameterizedTypeWrapper(
        AnnotatedType annotatedType, Type type, AnnotatedType[] typeArguments) {
      super(annotatedType, type);
      this.typeArguments = typeArguments.clone();
    }

    @Override
    public AnnotatedType[] getAnnotatedActualTypeArguments() {
      return typeArguments.clone();
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof AnnotatedParameterizedType)) {
        return false;
      }
      AnnotatedParameterizedType that = (AnnotatedParameterizedType) o;
      return equalsTypeAndAnnotations(that)
          && Arrays.equals(
              getAnnotatedActualTypeArguments(), that.getAnnotatedActualTypeArguments());
    }

    @Override
    public int hashCode() {
      return baseHashCode() ^ Objects.hash((Object[]) getAnnotatedActualTypeArguments());
    }
  }

  private static final Optional<Method> ANNOTATED_OWNER_TYPE_METHOD =
      findAnnotatedOwnerTypeMethod();

  private static Optional<Method> findAnnotatedOwnerTypeMethod() {
    try {
      return Optional.of(AnnotatedType.class.getMethod("getAnnotatedOwnerType"));
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }

  private static AnnotatedType getAnnotatedOwnerTypeOrNull(AnnotatedType annotatedType) {
    if (annotatedType == null || !ANNOTATED_OWNER_TYPE_METHOD.isPresent()) {
      return null;
    }
    try {
      return (AnnotatedType) ANNOTATED_OWNER_TYPE_METHOD.get().invoke(annotatedType);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }
}
