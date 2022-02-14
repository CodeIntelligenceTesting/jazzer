// Copyright 2021 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.autofuzz;

import com.code_intelligence.jazzer.api.AutofuzzConstructionException;
import com.code_intelligence.jazzer.api.AutofuzzInvocationException;
import com.code_intelligence.jazzer.api.Consumer1;
import com.code_intelligence.jazzer.api.Consumer2;
import com.code_intelligence.jazzer.api.Consumer3;
import com.code_intelligence.jazzer.api.Consumer4;
import com.code_intelligence.jazzer.api.Consumer5;
import com.code_intelligence.jazzer.api.Function1;
import com.code_intelligence.jazzer.api.Function2;
import com.code_intelligence.jazzer.api.Function3;
import com.code_intelligence.jazzer.api.Function4;
import com.code_intelligence.jazzer.api.Function5;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.utils.Utils;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfoList;
import io.github.classgraph.ScanResult;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import net.jodah.typetools.TypeResolver;
import net.jodah.typetools.TypeResolver.Unknown;

public class Meta {
  static WeakHashMap<Class<?>, List<Class<?>>> implementingClassesCache = new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Class<?>>> nestedBuilderClassesCache = new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Method>> originalObjectCreationMethodsCache =
      new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Method>> cascadingBuilderMethodsCache = new WeakHashMap<>();

  public static Object autofuzz(FuzzedDataProvider data, Method method) {
    return autofuzz(data, method, null);
  }

  static Object autofuzz(FuzzedDataProvider data, Method method, AutofuzzCodegenVisitor visitor) {
    Object result;
    if (Modifier.isStatic(method.getModifiers())) {
      if (visitor != null) {
        // This group will always have two elements: The class name and the method call.
        visitor.pushGroup(
            String.format("%s.", method.getDeclaringClass().getCanonicalName()), "", "");
      }
      try {
        result = autofuzz(data, method, null, visitor);
      } finally {
        if (visitor != null) {
          visitor.popGroup();
        }
      }
    } else {
      if (visitor != null) {
        // This group will always have two elements: The thisObject and the method call.
        // Since the this object can be a complex expression, wrap it in paranthesis.
        visitor.pushGroup("(", ").", "");
      }
      Object thisObject = consume(data, method.getDeclaringClass(), visitor);
      if (thisObject == null) {
        throw new AutofuzzConstructionException();
      }
      try {
        result = autofuzz(data, method, thisObject, visitor);
      } finally {
        if (visitor != null) {
          visitor.popGroup();
        }
      }
    }
    return result;
  }

  public static Object autofuzz(FuzzedDataProvider data, Method method, Object thisObject) {
    return autofuzz(data, method, thisObject, null);
  }

  static Object autofuzz(
      FuzzedDataProvider data, Method method, Object thisObject, AutofuzzCodegenVisitor visitor) {
    if (visitor != null) {
      visitor.pushGroup(String.format("%s(", method.getName()), ", ", ")");
    }
    Object[] arguments = consumeArguments(data, method, visitor);
    if (visitor != null) {
      visitor.popGroup();
    }
    try {
      return method.invoke(thisObject, arguments);
    } catch (IllegalAccessException | IllegalArgumentException | NullPointerException e) {
      // We should ensure that the arguments fed into the method are always valid.
      throw new AutofuzzError(getDebugSummary(method, thisObject, arguments), e);
    } catch (InvocationTargetException e) {
      throw new AutofuzzInvocationException(e.getCause());
    }
  }

  public static <R> R autofuzz(FuzzedDataProvider data, Constructor<R> constructor) {
    return autofuzz(data, constructor, null);
  }

  static <R> R autofuzz(
      FuzzedDataProvider data, Constructor<R> constructor, AutofuzzCodegenVisitor visitor) {
    if (visitor != null) {
      // getCanonicalName is correct also for nested classes.
      visitor.pushGroup(
          String.format("new %s(", constructor.getDeclaringClass().getCanonicalName()), ", ", ")");
    }
    Object[] arguments = consumeArguments(data, constructor, visitor);
    if (visitor != null) {
      visitor.popGroup();
    }
    try {
      return constructor.newInstance(arguments);
    } catch (InstantiationException | IllegalAccessException | IllegalArgumentException e) {
      // This should never be reached as the logic in consume should prevent us from e.g. calling
      // constructors of abstract classes or private constructors.
      throw new AutofuzzError(getDebugSummary(constructor, null, arguments), e);
    } catch (InvocationTargetException e) {
      throw new AutofuzzInvocationException(e.getCause());
    }
  }

  @SuppressWarnings("unchecked")
  public static <T1> void autofuzz(FuzzedDataProvider data, Consumer1<T1> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer1.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2> void autofuzz(FuzzedDataProvider data, Consumer2<T1, T2> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer2.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3> void autofuzz(FuzzedDataProvider data, Consumer3<T1, T2, T3> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer3.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4> void autofuzz(
      FuzzedDataProvider data, Consumer4<T1, T2, T3, T4> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer4.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5> void autofuzz(
      FuzzedDataProvider data, Consumer5<T1, T2, T3, T4, T5> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer5.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3),
        (T5) consumeChecked(data, types, 4));
  }

  @SuppressWarnings("unchecked")
  public static <T1, R> R autofuzz(FuzzedDataProvider data, Function1<T1, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function1.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, R> R autofuzz(FuzzedDataProvider data, Function2<T1, T2, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function2.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, R> R autofuzz(FuzzedDataProvider data, Function3<T1, T2, T3, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function3.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, R> R autofuzz(
      FuzzedDataProvider data, Function4<T1, T2, T3, T4, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function4.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5, R> R autofuzz(
      FuzzedDataProvider data, Function5<T1, T2, T3, T4, T5, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function5.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3),
        (T5) consumeChecked(data, types, 4));
  }

  public static Object consume(FuzzedDataProvider data, Class<?> type) {
    return consume(data, type, null);
  }

  // Invariant: The Java source code representation of the returned object visited by visitor must
  // represent an object of the same type as genericType. For example, a null value returned for
  // the genericType Class<java.lang.String> should lead to the generated code
  // "(java.lang.String) null", not just "null". This makes it possible to safely use consume in
  // recursive argument constructions.
  static Object consume(FuzzedDataProvider data, Type genericType, AutofuzzCodegenVisitor visitor) {
    Class<?> type = getRawType(genericType);
    if (type == byte.class || type == Byte.class) {
      byte result = data.consumeByte();
      if (visitor != null)
        visitor.pushElement(String.format("(byte) %s", result));
      return result;
    } else if (type == short.class || type == Short.class) {
      short result = data.consumeShort();
      if (visitor != null)
        visitor.pushElement(String.format("(short) %s", result));
      return result;
    } else if (type == int.class || type == Integer.class) {
      int result = data.consumeInt();
      if (visitor != null)
        visitor.pushElement(Integer.toString(result));
      return result;
    } else if (type == long.class || type == Long.class) {
      long result = data.consumeLong();
      if (visitor != null)
        visitor.pushElement(String.format("%sL", result));
      return result;
    } else if (type == float.class || type == Float.class) {
      float result = data.consumeFloat();
      if (visitor != null)
        visitor.pushElement(String.format("%sF", result));
      return result;
    } else if (type == double.class || type == Double.class) {
      double result = data.consumeDouble();
      if (visitor != null)
        visitor.pushElement(Double.toString(result));
      return result;
    } else if (type == boolean.class || type == Boolean.class) {
      boolean result = data.consumeBoolean();
      if (visitor != null)
        visitor.pushElement(Boolean.toString(result));
      return result;
    } else if (type == char.class || type == Character.class) {
      char result = data.consumeChar();
      if (visitor != null)
        visitor.addCharLiteral(result);
      return result;
    }
    // Return null for non-primitive and non-boxed types in ~5% of the cases.
    // TODO: We might want to return null for boxed types sometimes, but this is complicated by the
    //       fact that TypeUtils can't distinguish between a primitive type and its wrapper and may
    //       thus easily cause false-positive NullPointerExceptions.
    if (!type.isPrimitive() && data.consumeByte((byte) 0, (byte) 19) == 0) {
      if (visitor != null) {
        if (type == Object.class) {
          visitor.pushElement("null");
        } else {
          visitor.pushElement(String.format("(%s) null", type.getCanonicalName()));
        }
      }
      return null;
    }
    if (type == String.class || type == CharSequence.class) {
      String result = data.consumeString(consumeArrayLength(data, 1));
      if (visitor != null)
        visitor.addStringLiteral(result);
      return result;
    } else if (type.isArray()) {
      if (type == byte[].class) {
        byte[] result = data.consumeBytes(consumeArrayLength(data, Byte.BYTES));
        if (visitor != null) {
          visitor.pushElement(IntStream.range(0, result.length)
                                  .mapToObj(i -> "(byte) " + result[i])
                                  .collect(Collectors.joining(", ", "new byte[]{", "}")));
        }
        return result;
      } else if (type == int[].class) {
        int[] result = data.consumeInts(consumeArrayLength(data, Integer.BYTES));
        if (visitor != null) {
          visitor.pushElement(Arrays.stream(result)
                                  .mapToObj(String::valueOf)
                                  .collect(Collectors.joining(", ", "new int[]{", "}")));
        }
        return result;
      } else if (type == short[].class) {
        short[] result = data.consumeShorts(consumeArrayLength(data, Short.BYTES));
        if (visitor != null) {
          visitor.pushElement(IntStream.range(0, result.length)
                                  .mapToObj(i -> "(short) " + result[i])
                                  .collect(Collectors.joining(", ", "new short[]{", "}")));
        }
        return result;
      } else if (type == long[].class) {
        long[] result = data.consumeLongs(consumeArrayLength(data, Long.BYTES));
        if (visitor != null) {
          visitor.pushElement(Arrays.stream(result)
                                  .mapToObj(e -> e + "L")
                                  .collect(Collectors.joining(", ", "new long[]{", "}")));
        }
        return result;
      } else if (type == boolean[].class) {
        boolean[] result = data.consumeBooleans(consumeArrayLength(data, 1));
        if (visitor != null) {
          visitor.pushElement(
              Arrays.toString(result).replace(']', '}').replace("[", "new boolean[]{"));
        }
        return result;
      } else {
        if (visitor != null) {
          visitor.pushGroup(
              String.format("new %s[]{", type.getComponentType().getName()), ", ", "}");
        }
        int remainingBytesBeforeFirstElementCreation = data.remainingBytes();
        Object firstElement = consume(data, type.getComponentType(), visitor);
        int remainingBytesAfterFirstElementCreation = data.remainingBytes();
        int sizeOfElementEstimate =
            remainingBytesBeforeFirstElementCreation - remainingBytesAfterFirstElementCreation;
        Object array = Array.newInstance(
            type.getComponentType(), consumeArrayLength(data, sizeOfElementEstimate));
        for (int i = 0; i < Array.getLength(array); i++) {
          if (i == 0) {
            Array.set(array, i, firstElement);
          } else {
            Array.set(array, i, consume(data, type.getComponentType(), visitor));
          }
        }
        if (visitor != null) {
          if (Array.getLength(array) == 0) {
            // We implicitly pushed the first element with the call to consume above, but it is not
            // part of the array.
            visitor.popElement();
          }
          visitor.popGroup();
        }
        return array;
      }
    } else if (type == ByteArrayInputStream.class || type == InputStream.class) {
      byte[] array = data.consumeBytes(consumeArrayLength(data, Byte.BYTES));
      if (visitor != null) {
        visitor.pushElement(IntStream.range(0, array.length)
                                .mapToObj(i -> "(byte) " + array[i])
                                .collect(Collectors.joining(
                                    ", ", "new java.io.ByteArrayInputStream(new byte[]{", "})")));
      }
      return new ByteArrayInputStream(array);
    } else if (type == Map.class) {
      ParameterizedType mapType = (ParameterizedType) genericType;
      if (mapType.getActualTypeArguments().length != 2) {
        throw new AutofuzzError(
            "Expected Map generic type to have two type parameters: " + mapType);
      }
      Type keyType = mapType.getActualTypeArguments()[0];
      Type valueType = mapType.getActualTypeArguments()[1];
      if (visitor != null) {
        // Do not use Collectors.toMap() since it cannot handle null values.
        // Also annotate the type of the entry stream since it might be empty, in which case type
        // inference on the accumulator could fail.
        visitor.pushGroup(
            String.format("java.util.stream.Stream.<java.util.AbstractMap.SimpleEntry<%s, %s>>of(",
                keyType.getTypeName(), valueType.getTypeName()),
            ", ",
            ").collect(java.util.HashMap::new, (map, e) -> map.put(e.getKey(), e.getValue()), java.util.HashMap::putAll)");
      }
      int remainingBytesBeforeFirstEntryCreation = data.remainingBytes();
      if (visitor != null) {
        visitor.pushGroup("new java.util.AbstractMap.SimpleEntry<>(", ", ", ")");
      }
      Object firstKey = consume(data, keyType, visitor);
      Object firstValue = consume(data, valueType, visitor);
      if (visitor != null) {
        visitor.popGroup();
      }
      int remainingBytesAfterFirstEntryCreation = data.remainingBytes();
      int sizeOfElementEstimate =
          remainingBytesBeforeFirstEntryCreation - remainingBytesAfterFirstEntryCreation;
      int mapSize = consumeArrayLength(data, sizeOfElementEstimate);
      Map<Object, Object> map = new HashMap<>(mapSize);
      for (int i = 0; i < mapSize; i++) {
        if (i == 0) {
          map.put(firstKey, firstValue);
        } else {
          if (visitor != null) {
            visitor.pushGroup("new java.util.AbstractMap.SimpleEntry<>(", ", ", ")");
          }
          map.put(consume(data, keyType, visitor), consume(data, valueType, visitor));
          if (visitor != null) {
            visitor.popGroup();
          }
        }
      }
      if (visitor != null) {
        if (mapSize == 0) {
          // We implicitly pushed the first entry with the call to consume above, but it is not
          // part of the array.
          visitor.popElement();
        }
        visitor.popGroup();
      }
      return map;
    } else if (type.isEnum()) {
      Enum<?> enumValue = (Enum<?>) data.pickValue(type.getEnumConstants());
      if (visitor != null) {
        visitor.pushElement(String.format("%s.%s", type.getName(), enumValue.name()));
      }
      return enumValue;
    } else if (type == Class.class) {
      if (visitor != null)
        visitor.pushElement(String.format("%s.class", YourAverageJavaClass.class.getName()));
      return YourAverageJavaClass.class;
    } else if (type == Method.class) {
      if (visitor != null) {
        throw new AutofuzzError("codegen has not been implemented for Method.class");
      }
      return data.pickValue(sortExecutables(YourAverageJavaClass.class.getMethods()));
    } else if (type == Constructor.class) {
      if (visitor != null) {
        throw new AutofuzzError("codegen has not been implemented for Constructor.class");
      }
      return data.pickValue(sortExecutables(YourAverageJavaClass.class.getConstructors()));
    } else if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
      List<Class<?>> implementingClasses = implementingClassesCache.get(type);
      if (implementingClasses == null) {
        ClassGraph classGraph =
            new ClassGraph().enableClassInfo().enableInterClassDependencies().rejectPackages(
                "jaz.*");
        if (!isTest()) {
          classGraph.rejectPackages("com.code_intelligence.jazzer.*");
        }
        try (ScanResult result = classGraph.scan()) {
          ClassInfoList children =
              type.isInterface() ? result.getClassesImplementing(type) : result.getSubclasses(type);
          implementingClasses =
              children.getStandardClasses().filter(cls -> !cls.isAbstract()).loadClasses();
          implementingClassesCache.put(type, implementingClasses);
        }
      }
      if (implementingClasses.isEmpty()) {
        if (isDebug()) {
          throw new AutofuzzConstructionException(String.format(
              "Could not find classes implementing %s on the classpath", type.getName()));
        } else {
          throw new AutofuzzConstructionException();
        }
      }
      if (visitor != null) {
        // This group will always have a single element: The instance of the implementing class.
        visitor.pushGroup(String.format("(%s) ", type.getName()), "", "");
      }
      Object result = consume(data, data.pickValue(implementingClasses), visitor);
      if (visitor != null) {
        visitor.popGroup();
      }
      return result;
    } else if (type.getConstructors().length > 0) {
      Constructor<?> constructor = data.pickValue(sortExecutables(type.getConstructors()));
      boolean applySetters = constructor.getParameterCount() == 0;
      if (visitor != null && applySetters) {
        // Embed the instance creation and setters into an immediately invoked lambda expression to
        // turn them into an expression.
        String uniqueVariableName = visitor.uniqueVariableName();
        visitor.pushGroup(String.format("((java.util.function.Supplier<%1$s>) (() -> {%1$s %2$s = ",
                              type.getCanonicalName(), uniqueVariableName),
            String.format("; %s.", uniqueVariableName),
            String.format("; return %s;})).get()", uniqueVariableName));
      }
      Object obj = autofuzz(data, constructor, visitor);
      if (applySetters) {
        List<Method> potentialSetters = getPotentialSetters(type);
        if (!potentialSetters.isEmpty()) {
          List<Method> pickedSetters =
              data.pickValues(potentialSetters, data.consumeInt(0, potentialSetters.size()));
          for (Method setter : pickedSetters) {
            autofuzz(data, setter, obj, visitor);
          }
        }
        if (visitor != null) {
          visitor.popGroup();
        }
      }
      return obj;
    }
    // We are out of more or less canonical ways to construct an instance of this class and have to
    // resort to more heuristic approaches.

    // First, try to find nested classes with names ending in Builder and call a subset of their
    // chaining methods.
    List<Class<?>> nestedBuilderClasses = getNestedBuilderClasses(type);
    if (!nestedBuilderClasses.isEmpty()) {
      Class<?> pickedBuilder = data.pickValue(nestedBuilderClasses);
      List<Method> cascadingBuilderMethods = getCascadingBuilderMethods(pickedBuilder);
      List<Method> originalObjectCreationMethods = getOriginalObjectCreationMethods(pickedBuilder);

      int pickedMethodsNumber = data.consumeInt(0, cascadingBuilderMethods.size());
      List<Method> pickedMethods = data.pickValues(cascadingBuilderMethods, pickedMethodsNumber);
      Method builderMethod = data.pickValue(originalObjectCreationMethods);

      if (visitor != null) {
        // Group for the chain of builder methods.
        visitor.pushGroup("", ".", "");
      }
      Object builderObj =
          autofuzz(data, data.pickValue(sortExecutables(pickedBuilder.getConstructors())), visitor);
      for (Method method : pickedMethods) {
        builderObj = autofuzz(data, method, builderObj, visitor);
      }

      try {
        Object obj = autofuzz(data, builderMethod, builderObj, visitor);
        if (visitor != null) {
          visitor.popGroup();
        }
        return obj;
      } catch (Exception e) {
        throw new AutofuzzConstructionException(e);
      }
    }

    // We ran out of ways to construct an instance of the requested type. If in debug mode, report
    // more detailed information.
    if (!isDebug()) {
      throw new AutofuzzConstructionException();
    } else {
      String summary = String.format(
          "Failed to generate instance of %s:%nAccessible constructors: %s%nNested subclasses: %s%n",
          type.getName(),
          Arrays.stream(type.getConstructors())
              .map(Utils::getReadableDescriptor)
              .collect(Collectors.joining(", ")),
          Arrays.stream(type.getClasses()).map(Class::getName).collect(Collectors.joining(", ")));
      throw new AutofuzzConstructionException(summary);
    }
  }

  static void rescanClasspath() {
    implementingClassesCache.clear();
  }

  static boolean isTest() {
    String value = System.getenv("JAZZER_AUTOFUZZ_TESTING");
    return value != null && !value.isEmpty();
  }

  static boolean isDebug() {
    String value = System.getenv("JAZZER_AUTOFUZZ_DEBUG");
    return value != null && !value.isEmpty();
  }

  private static int consumeArrayLength(FuzzedDataProvider data, int sizeOfElement) {
    // Spend at most half of the fuzzer input bytes so that the remaining arguments that require
    // construction still have non-trivial data to work with.
    int bytesToSpend = data.remainingBytes() / 2;
    return bytesToSpend / Math.max(sizeOfElement, 1);
  }

  private static String getDebugSummary(
      Executable executable, Object thisObject, Object[] arguments) {
    return String.format("%nMethod: %s::%s%s%nthis: %s%nArguments: %s",
        executable.getDeclaringClass().getName(), executable.getName(),
        Utils.getReadableDescriptor(executable), thisObject,
        Arrays.stream(arguments)
            .map(arg -> arg == null ? "null" : arg.toString())
            .collect(Collectors.joining(", ")));
  }

  private static <T extends Executable> List<T> sortExecutables(T[] executables) {
    List<T> list = Arrays.asList(executables);
    sortExecutables(list);
    return list;
  }

  private static void sortExecutables(List<? extends Executable> executables) {
    executables.sort(Comparator.comparing(Executable::getName).thenComparing(Utils::getDescriptor));
  }

  private static void sortClasses(List<? extends Class<?>> classes) {
    classes.sort(Comparator.comparing(Class::getName));
  }

  private static List<Class<?>> getNestedBuilderClasses(Class<?> type) {
    List<Class<?>> nestedBuilderClasses = nestedBuilderClassesCache.get(type);
    if (nestedBuilderClasses == null) {
      nestedBuilderClasses = Arrays.stream(type.getClasses())
                                 .filter(cls -> cls.getName().endsWith("Builder"))
                                 .filter(cls -> !getOriginalObjectCreationMethods(cls).isEmpty())
                                 .collect(Collectors.toList());
      sortClasses(nestedBuilderClasses);
      nestedBuilderClassesCache.put(type, nestedBuilderClasses);
    }
    return nestedBuilderClasses;
  }

  private static List<Method> getOriginalObjectCreationMethods(Class<?> builder) {
    List<Method> originalObjectCreationMethods = originalObjectCreationMethodsCache.get(builder);
    if (originalObjectCreationMethods == null) {
      originalObjectCreationMethods =
          Arrays.stream(builder.getMethods())
              .filter(m -> m.getReturnType() == builder.getEnclosingClass())
              .collect(Collectors.toList());
      sortExecutables(originalObjectCreationMethods);
      originalObjectCreationMethodsCache.put(builder, originalObjectCreationMethods);
    }
    return originalObjectCreationMethods;
  }

  private static List<Method> getCascadingBuilderMethods(Class<?> builder) {
    List<Method> cascadingBuilderMethods = cascadingBuilderMethodsCache.get(builder);
    if (cascadingBuilderMethods == null) {
      cascadingBuilderMethods = Arrays.stream(builder.getMethods())
                                    .filter(m -> m.getReturnType() == builder)
                                    .collect(Collectors.toList());
      sortExecutables(cascadingBuilderMethods);
      cascadingBuilderMethodsCache.put(builder, cascadingBuilderMethods);
    }
    return cascadingBuilderMethods;
  }

  private static List<Method> getPotentialSetters(Class<?> type) {
    List<Method> potentialSetters = new ArrayList<>();
    Method[] methods = type.getMethods();
    for (Method method : methods) {
      if (void.class.equals(method.getReturnType()) && method.getParameterCount() == 1
          && method.getName().startsWith("set")) {
        potentialSetters.add(method);
      }
    }
    sortExecutables(potentialSetters);
    return potentialSetters;
  }

  private static Object[] consumeArguments(
      FuzzedDataProvider data, Executable executable, AutofuzzCodegenVisitor visitor) {
    Object[] result;
    try {
      result = Arrays.stream(executable.getGenericParameterTypes())
                   .map((type) -> consume(data, type, visitor))
                   .toArray();
      return result;
    } catch (AutofuzzConstructionException e) {
      // Do not nest AutofuzzConstructionExceptions.
      throw e;
    } catch (AutofuzzInvocationException e) {
      // If an invocation fails while creating the arguments for another invocation, the exception
      // should not be reported, so we rewrap it.
      throw new AutofuzzConstructionException(e.getCause());
    } catch (Throwable t) {
      throw new AutofuzzConstructionException(t);
    }
  }

  private static Object consumeChecked(FuzzedDataProvider data, Class<?>[] types, int i) {
    if (types[i] == Unknown.class) {
      throw new AutofuzzError("Failed to determine type of argument " + (i + 1));
    }
    Object result;
    try {
      result = consume(data, types[i]);
    } catch (AutofuzzConstructionException e) {
      // Do not nest AutofuzzConstructionExceptions.
      throw e;
    } catch (AutofuzzInvocationException e) {
      // If an invocation fails while creating the arguments for another invocation, the exception
      // should not be reported, so we rewrap it.
      throw new AutofuzzConstructionException(e.getCause());
    } catch (Throwable t) {
      throw new AutofuzzConstructionException(t);
    }
    if (result != null && !types[i].isAssignableFrom(result.getClass())) {
      throw new AutofuzzError("consume returned " + result.getClass() + ", but need " + types[i]);
    }
    return result;
  }

  private static Class<?> getRawType(Type genericType) {
    if (genericType instanceof Class<?>) {
      return (Class<?>) genericType;
    } else if (genericType instanceof ParameterizedType) {
      return getRawType(((ParameterizedType) genericType).getRawType());
    } else if (genericType instanceof WildcardType) {
      // TODO: Improve this.
      return Object.class;
    } else if (genericType instanceof TypeVariable<?>) {
      throw new AutofuzzError("Did not expect genericType to be a TypeVariable: " + genericType);
    } else if (genericType instanceof GenericArrayType) {
      // TODO: Improve this;
      return Object[].class;
    } else {
      throw new AutofuzzError("Got unexpected class implementing Type: " + genericType);
    }
  }
}
