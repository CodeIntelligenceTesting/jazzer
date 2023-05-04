/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.check;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.requireNonNullElements;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import java.lang.annotation.Annotation;
import java.lang.annotation.Inherited;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.AnnotatedParameterizedType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.AnnotatedTypeVariable;
import java.lang.reflect.AnnotatedWildcardType;
import java.lang.reflect.Array;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class TypeSupport {
  private static final Annotation NOT_NULL =
      new TypeHolder<@NotNull String>() {}.annotatedType().getAnnotation(NotNull.class);

  private TypeSupport() {}

  public static boolean isPrimitive(AnnotatedType type) {
    return isPrimitive(type.getType());
  }

  public static boolean isPrimitive(Type type) {
    if (!(type instanceof Class<?>) ) {
      return false;
    }
    return ((Class<?>) type).isPrimitive();
  }

  public static boolean isInheritable(Annotation annotation) {
    return annotation.annotationType().getDeclaredAnnotation(Inherited.class) != null;
  }

  /**
   * Returns {@code type} as a {@code Class<? extends T>} if it is a subclass of T, otherwise
   * empty.
   *
   * <p>This function also returns an empty {@link Optional} for more complex (e.g. parameterized)
   * types.
   */
  public static <T> Optional<Class<? extends T>> asSubclassOrEmpty(
      AnnotatedType type, Class<T> superclass) {
    if (!(type.getType() instanceof Class<?>) ) {
      return Optional.empty();
    }

    Class<?> actualClazz = (Class<?>) type.getType();
    if (!superclass.isAssignableFrom(actualClazz)) {
      return Optional.empty();
    }

    return Optional.of(actualClazz.asSubclass(superclass));
  }

  public static AnnotatedType asAnnotatedType(Class<?> clazz) {
    requireNonNull(clazz);
    return new AnnotatedType() {
      @Override
      public Type getType() {
        return clazz;
      }

      @Override
      public <T extends Annotation> T getAnnotation(Class<T> annotationClass) {
        return annotatedElementGetAnnotation(this, annotationClass);
      }

      @Override
      public Annotation[] getAnnotations() {
        // No directly present annotations, look for inheritable present annotations on the
        // superclass.
        if (clazz.getSuperclass() == null) {
          return new Annotation[0];
        }
        return stream(clazz.getSuperclass().getAnnotations())
            .filter(TypeSupport::isInheritable)
            .toArray(Annotation[] ::new);
      }

      @Override
      public Annotation[] getDeclaredAnnotations() {
        // No directly present annotations.
        return new Annotation[0];
      }

      @Override
      public String toString() {
        return annotatedTypeToString(this);
      }

      @Override
      public int hashCode() {
        throw new UnsupportedOperationException(
            "hashCode() is not supported as its behavior isn't specified");
      }

      @Override
      public boolean equals(Object obj) {
        throw new UnsupportedOperationException(
            "equals() is not supported as its behavior isn't specified");
      }
    };
  }

  /**
   * Visits the individual classes and their directly present annotations that make up the given
   * type.
   *
   * <p>Classes are visited in left-to-right order as they appear in the type definition, except
   * that an array class is visited before its component class.
   *
   * @throws IllegalArgumentException if the given type contains a wildcard type or type variable
   */
  public static void visitAnnotatedType(
      AnnotatedType type, BiConsumer<Class<?>, Annotation[]> visitor) {
    visitAnnotatedTypeInternal(type, visitor);
  }

  private static Class<?> visitAnnotatedTypeInternal(
      AnnotatedType type, BiConsumer<Class<?>, Annotation[]> visitor) {
    Class<?> clazz;
    if (type instanceof AnnotatedWildcardType) {
      throw new IllegalArgumentException("Wildcard types are not supported: " + type);
    } else if (type instanceof AnnotatedTypeVariable) {
      throw new IllegalArgumentException("Type variables are not supported: " + type);
    } else if (type instanceof AnnotatedParameterizedType) {
      AnnotatedParameterizedType annotatedParameterizedType = (AnnotatedParameterizedType) type;
      check(annotatedParameterizedType.getType() instanceof ParameterizedType);
      Type rawType = ((ParameterizedType) annotatedParameterizedType.getType()).getRawType();
      check(rawType instanceof Class<?>);
      clazz = (Class<?>) rawType;

      visitor.accept(clazz, type.getDeclaredAnnotations());
      for (AnnotatedType typeArgument :
          annotatedParameterizedType.getAnnotatedActualTypeArguments()) {
        visitAnnotatedTypeInternal(typeArgument, visitor);
      }
    } else if (type instanceof AnnotatedArrayType) {
      AnnotatedArrayType arrayType = (AnnotatedArrayType) type;

      // Recursively determine the array class before visiting the component type.
      Class<?> componentClass =
          visitAnnotatedTypeInternal(arrayType.getAnnotatedGenericComponentType(), (c, a) -> {});
      clazz = Array.newInstance(componentClass, 0).getClass();
      visitor.accept(clazz, type.getDeclaredAnnotations());
      visitAnnotatedTypeInternal(arrayType.getAnnotatedGenericComponentType(), visitor);
    } else {
      check(type.getType() instanceof Class<?>);
      clazz = (Class<?>) type.getType();

      visitor.accept(clazz, type.getDeclaredAnnotations());
    }
    return clazz;
  }

  public static AnnotatedType notNull(AnnotatedType type) {
    return withExtraAnnotations(type, NOT_NULL);
  }

  /**
   * Constructs an anonymous WithLength class that can be applied as an annotation to {@code type}
   * with the given
   * {@code min} and {@code max} values.
   * @param type
   * @param min
   * @param max
   * @return {@code type} with a `WithLength` annotation applied to it
   */
  public static AnnotatedType withLength(AnnotatedType type, int min, int max) {
    WithLength withLength = withLengthImplementation(min, max);
    return withExtraAnnotations(type, withLength);
  }

  private static WithLength withLengthImplementation(int min, int max) {
    return new WithLength() {
      @Override
      public int min() {
        return min;
      }

      @Override
      public int max() {
        return max;
      }

      @Override
      public Class<? extends Annotation> annotationType() {
        return WithLength.class;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof WithLength)) {
          return false;
        }
        WithLength other = (WithLength) o;
        return this.min() == other.min() && this.max() == other.max();
      }

      @Override
      public int hashCode() {
        int hash = 0;
        hash += ("min".hashCode() * 127) ^ Integer.valueOf(this.min()).hashCode();
        hash += ("max".hashCode() * 127) ^ Integer.valueOf(this.max()).hashCode();
        return hash;
      }
    };
  }

  public static AnnotatedParameterizedType withTypeArguments(
      AnnotatedType type, AnnotatedType... typeArguments) {
    requireNonNull(type);
    requireNonNullElements(typeArguments);
    require(typeArguments.length > 0);
    require(!(type instanceof AnnotatedParameterizedType || type instanceof AnnotatedTypeVariable
                || type instanceof AnnotatedWildcardType || type instanceof AnnotatedArrayType),
        "only plain annotated types are supported");
    require(
        ((Class<?>) type.getType()).getEnclosingClass() == null, "nested classes aren't supported");

    ParameterizedType filledRawType = new ParameterizedType() {
      @Override
      public Type[] getActualTypeArguments() {
        return stream(typeArguments).map(AnnotatedType::getType).toArray(Type[] ::new);
      }

      @Override
      public Type getRawType() {
        return type.getType();
      }

      @Override
      public Type getOwnerType() {
        // We require the class is top-level.
        return null;
      }

      @Override
      public String toString() {
        return getRawType()
            + stream(getActualTypeArguments()).map(Type::toString).collect(joining(",", "<", ">"));
      }

      @Override
      public boolean equals(Object obj) {
        if (!(obj instanceof ParameterizedType)) {
          return false;
        }
        ParameterizedType other = (ParameterizedType) obj;
        return getRawType().equals(other.getRawType()) && null == other.getOwnerType()
            && Arrays.equals(getActualTypeArguments(), other.getActualTypeArguments());
      }

      @Override
      public int hashCode() {
        throw new UnsupportedOperationException(
            "hashCode() is not supported as its behavior isn't specified");
      }
    };

    return new AnnotatedParameterizedType() {
      @Override
      public AnnotatedType[] getAnnotatedActualTypeArguments() {
        return Arrays.copyOf(typeArguments, typeArguments.length);
      }

      // @Override as of Java 9
      @SuppressWarnings("Since15")
      public AnnotatedType getAnnotatedOwnerType() {
        return null;
      }

      @Override
      public Type getType() {
        return filledRawType;
      }

      @Override
      public <T extends Annotation> T getAnnotation(Class<T> annotationClass) {
        return type.getAnnotation(annotationClass);
      }

      @Override
      public Annotation[] getAnnotations() {
        return type.getAnnotations();
      }

      @Override
      public Annotation[] getDeclaredAnnotations() {
        return type.getDeclaredAnnotations();
      }

      @Override
      public String toString() {
        return annotatedTypeToString(this);
      }

      @Override
      public boolean equals(Object obj) {
        if (!(obj instanceof AnnotatedParameterizedType)) {
          return false;
        }
        AnnotatedParameterizedType other = (AnnotatedParameterizedType) obj;
        // Can't call getAnnotatedOwnerType on Java 8, but since our own implementation always
        // returns null, comparing getType().getOwnerType() via getType() is sufficient.
        return Objects.equals(getType(), other.getType())
            && Arrays.equals(
                getAnnotatedActualTypeArguments(), other.getAnnotatedActualTypeArguments())
            && Arrays.equals(getAnnotations(), other.getAnnotations());
      }

      @Override
      public int hashCode() {
        throw new UnsupportedOperationException(
            "hashCode() is not supported as its behavior isn't specified");
      }
    };
  }

  public static AnnotatedType withExtraAnnotations(
      AnnotatedType base, Annotation... extraAnnotations) {
    requireNonNull(base);
    requireNonNullElements(extraAnnotations);

    if (extraAnnotations.length == 0) {
      return base;
    }

    require(!(base instanceof AnnotatedTypeVariable || base instanceof AnnotatedWildcardType),
        "Adding annotations to AnnotatedTypeVariables or AnnotatedWildcardTypes is not supported");
    if (base instanceof AnnotatedArrayType) {
      return new AugmentedArrayType((AnnotatedArrayType) base, extraAnnotations);
    } else if (base instanceof AnnotatedParameterizedType) {
      return new AugmentedParameterizedType((AnnotatedParameterizedType) base, extraAnnotations);
    } else {
      return new AugmentedAnnotatedType(base, extraAnnotations);
    }
  }

  private static String annotatedTypeToString(AnnotatedType annotatedType) {
    String annotations =
        stream(annotatedType.getAnnotations()).map(Annotation::toString).collect(joining(" "));
    if (annotations.isEmpty()) {
      return annotatedType.getType().toString();
    } else {
      return annotations + " " + annotatedType.getType();
    }
  }

  private static <T extends Annotation> T annotatedElementGetAnnotation(
      AnnotatedElement element, Class<T> annotationClass) {
    requireNonNull(annotationClass);
    return stream(element.getAnnotations())
        .filter(annotation -> annotationClass.equals(annotation.annotationType()))
        .findFirst()
        .map(annotationClass::cast)
        .orElse(null);
  }

  public static Optional<Class<?>> findFirstParentIfClass(AnnotatedType type, Class<?>... parents) {
    if (!(type.getType() instanceof Class<?>) ) {
      return Optional.empty();
    }
    Class<?> clazz = (Class<?>) type.getType();
    return Stream.of(parents).filter(parent -> parent.isAssignableFrom(clazz)).findFirst();
  }

  public static Optional<AnnotatedType> parameterTypeIfParameterized(
      AnnotatedType type, Class<?> expectedParent) {
    return parameterTypesIfParameterized(type, expectedParent).flatMap(typeArguments -> {
      if (typeArguments.size() != 1) {
        return Optional.empty();
      } else {
        AnnotatedType elementType = typeArguments.get(0);
        if (!(elementType.getType() instanceof ParameterizedType)
            && !(elementType.getType() instanceof Class)) {
          return Optional.empty();
        } else {
          return Optional.of(elementType);
        }
      }
    });
  }

  public static Optional<List<AnnotatedType>> parameterTypesIfParameterized(
      AnnotatedType type, Class<?> expectedParent) {
    if (!(type instanceof AnnotatedParameterizedType)) {
      return Optional.empty();
    }
    Class<?> clazz = (Class<?>) ((ParameterizedType) type.getType()).getRawType();
    if (!expectedParent.isAssignableFrom(clazz)) {
      return Optional.empty();
    }

    AnnotatedType[] typeArguments =
        ((AnnotatedParameterizedType) type).getAnnotatedActualTypeArguments();
    if (typeArguments.length == 0) {
      return Optional.empty();
    }
    return Optional.of(Collections.unmodifiableList(Arrays.asList(typeArguments)));
  }

  /**
   * Whether {@code root} is contained in a directed cycle in the directed graph rooted at it and
   * defined by the given {@code successors} function.
   */
  public static <T> boolean containedInDirectedCycle(T root, Function<T, Stream<T>> successors) {
    HashSet<T> traversed = new HashSet<>();
    ArrayDeque<T> toTraverse = new ArrayDeque<>();
    toTraverse.addLast(root);
    T currentNode;
    while ((currentNode = toTraverse.pollLast()) != null) {
      if (traversed.add(currentNode)) {
        successors.apply(currentNode).forEachOrdered(toTraverse::addLast);
      } else if (currentNode.equals(root)) {
        return true;
      }
    }
    return false;
  }

  private static class AugmentedArrayType
      extends AugmentedAnnotatedType implements AnnotatedArrayType {
    private AugmentedArrayType(AnnotatedArrayType base, Annotation[] extraAnnotations) {
      super(base, extraAnnotations);
    }

    @Override
    public AnnotatedType getAnnotatedGenericComponentType() {
      return ((AnnotatedArrayType) base).getAnnotatedGenericComponentType();
    }

    // @Override as of Java 9
    @SuppressWarnings("Since15")
    public AnnotatedType getAnnotatedOwnerType() {
      throw new UnsupportedOperationException("Not implemented");
    }
  }

  private static class AugmentedParameterizedType
      extends AugmentedAnnotatedType implements AnnotatedParameterizedType {
    private AugmentedParameterizedType(
        AnnotatedParameterizedType base, Annotation[] extraAnnotations) {
      super(base, extraAnnotations);
    }

    @Override
    public AnnotatedType[] getAnnotatedActualTypeArguments() {
      return ((AnnotatedParameterizedType) base).getAnnotatedActualTypeArguments();
    }

    // @Override as of Java 9
    @SuppressWarnings("Since15")
    public AnnotatedType getAnnotatedOwnerType() {
      throw new UnsupportedOperationException("Not implemented");
    }
  }

  private static class AugmentedAnnotatedType implements AnnotatedType {
    protected final AnnotatedType base;
    private final Annotation[] extraAnnotations;

    private AugmentedAnnotatedType(AnnotatedType base, Annotation[] extraAnnotations) {
      this.base = requireNonNull(base);
      this.extraAnnotations = checkExtraAnnotations(base, extraAnnotations);
    }

    private static Annotation[] checkExtraAnnotations(
        AnnotatedElement base, Annotation[] extraAnnotations) {
      requireNonNullElements(extraAnnotations);
      Set<Class<? extends Annotation>> existingAnnotationTypes =
          stream(base.getDeclaredAnnotations())
              .map(Annotation::annotationType)
              .collect(Collectors.toCollection(HashSet::new));
      for (Annotation annotation : extraAnnotations) {
        boolean added = existingAnnotationTypes.add(annotation.annotationType());
        require(added, annotation + " already directly present on " + base);
      }
      return extraAnnotations;
    }

    @Override
    public Type getType() {
      return base.getType();
    }

    @Override
    public <T extends Annotation> T getAnnotation(Class<T> annotationClass) {
      return annotatedElementGetAnnotation(this, annotationClass);
    }

    @Override
    public Annotation[] getAnnotations() {
      Set<Class<? extends Annotation>> directlyPresentTypes =
          stream(getDeclaredAnnotations()).map(Annotation::annotationType).collect(toSet());
      return Stream
          .concat(
              // Directly present annotations.
              stream(getDeclaredAnnotations()),
              // Present but not directly present annotations, never added by us as we don't add
              // annotations to the super class.
              stream(base.getAnnotations())
                  .filter(
                      annotation -> !directlyPresentTypes.contains(annotation.annotationType())))
          .toArray(Annotation[] ::new);
    }

    @Override
    public Annotation[] getDeclaredAnnotations() {
      return Stream.concat(stream(base.getDeclaredAnnotations()), stream(extraAnnotations))
          .toArray(Annotation[] ::new);
    }

    @Override
    public String toString() {
      return annotatedTypeToString(this);
    }

    @Override
    public boolean equals(Object obj) {
      throw new UnsupportedOperationException(
          "equals() is not supported as its behavior isn't specified");
    }

    @Override
    public int hashCode() {
      throw new UnsupportedOperationException(
          "hashCode() is not supported as its behavior isn't specified");
    }
  }
}
