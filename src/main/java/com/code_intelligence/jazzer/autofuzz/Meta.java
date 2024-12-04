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
import com.code_intelligence.jazzer.runtime.HardToCatchError;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import net.jodah.typetools.TypeResolver;
import net.jodah.typetools.TypeResolver.Unknown;

public class Meta {
  public static final boolean IS_DEBUG = isDebug();

  private static final Meta PUBLIC_LOOKUP_INSTANCE = new Meta(null);
  private static final boolean IS_TEST = isTest();
  private static final WeakHashMap<Class<?>, List<Class<?>>> implementingClassesCache =
      new WeakHashMap<>();
  private static final WeakHashMap<Class<?>, List<Class<?>>> nestedBuilderClassesCache =
      new WeakHashMap<>();
  private static final WeakHashMap<Class<?>, List<Method>> originalObjectCreationMethodsCache =
      new WeakHashMap<>();
  private static final WeakHashMap<Class<?>, List<Method>> cascadingBuilderMethodsCache =
      new WeakHashMap<>();

  private final AccessibleObjectLookup lookup;

  public Meta(Class<?> referenceClass) {
    lookup = new AccessibleObjectLookup(referenceClass);
  }

  @SuppressWarnings("unchecked")
  public static <T1> void autofuzz(FuzzedDataProvider data, Consumer1<T1> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer1.class, func.getClass());
    func.accept((T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2> void autofuzz(FuzzedDataProvider data, Consumer2<T1, T2> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer2.class, func.getClass());
    func.accept(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3> void autofuzz(FuzzedDataProvider data, Consumer3<T1, T2, T3> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer3.class, func.getClass());
    func.accept(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1),
        (T3) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 2));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4> void autofuzz(
      FuzzedDataProvider data, Consumer4<T1, T2, T3, T4> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer4.class, func.getClass());
    func.accept(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1),
        (T3) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 2),
        (T4) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 3));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5> void autofuzz(
      FuzzedDataProvider data, Consumer5<T1, T2, T3, T4, T5> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer5.class, func.getClass());
    func.accept(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1),
        (T3) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 2),
        (T4) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 3),
        (T5) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 4));
  }

  @SuppressWarnings("unchecked")
  public static <T1, R> R autofuzz(FuzzedDataProvider data, Function1<T1, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function1.class, func.getClass());
    return func.apply((T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, R> R autofuzz(FuzzedDataProvider data, Function2<T1, T2, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function2.class, func.getClass());
    return func.apply(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, R> R autofuzz(FuzzedDataProvider data, Function3<T1, T2, T3, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function3.class, func.getClass());
    return func.apply(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1),
        (T3) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 2));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, R> R autofuzz(
      FuzzedDataProvider data, Function4<T1, T2, T3, T4, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function4.class, func.getClass());
    return func.apply(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1),
        (T3) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 2),
        (T4) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 3));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5, R> R autofuzz(
      FuzzedDataProvider data, Function5<T1, T2, T3, T4, T5, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function5.class, func.getClass());
    return func.apply(
        (T1) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 0),
        (T2) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 1),
        (T3) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 2),
        (T4) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 3),
        (T5) PUBLIC_LOOKUP_INSTANCE.consumeChecked(data, types, 4));
  }

  public static Object consume(FuzzedDataProvider data, Class<?> type) {
    return PUBLIC_LOOKUP_INSTANCE.consume(data, type, null);
  }

  static void rescanClasspath() {
    implementingClassesCache.clear();
  }

  private static boolean isTest() {
    String value = System.getenv("JAZZER_AUTOFUZZ_TESTING");
    return value != null && !value.isEmpty();
  }

  private static boolean isDebug() {
    String value = System.getenv("JAZZER_AUTOFUZZ_DEBUG");
    return value != null && !value.isEmpty();
  }

  private static int consumeArrayLength(FuzzedDataProvider data, int sizeOfElement) {
    // Spend at most half of the fuzzer input bytes so that the remaining arguments that require
    // construction still have non-trivial data to work with.
    int bytesToSpend = data.remainingBytes() / 2;
    return bytesToSpend / Math.max(sizeOfElement, 1);
  }

  private static String deepToString(Object obj) {
    if (obj == null) {
      return "null";
    }
    if (obj.getClass().isArray()) {
      return String.format(
          "(%s[]) %s",
          obj.getClass().getComponentType().getName(), Arrays.deepToString((Object[]) obj));
    }
    return obj.toString();
  }

  private static String getDebugSummary(
      Executable executable, Object thisObject, Object[] arguments) {
    return String.format(
        "%nMethod: %s::%s%s%nthis: %s%nArguments: %s",
        executable.getDeclaringClass().getName(),
        executable.getName(),
        Utils.getReadableDescriptor(executable),
        thisObject,
        Arrays.stream(arguments).map(Meta::deepToString).collect(Collectors.joining(", ")));
  }

  static Class<?> getRawType(Type genericType) {
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
      return Array.newInstance(
              getRawType(((GenericArrayType) genericType).getGenericComponentType()), 0)
          .getClass();
    } else {
      throw new AutofuzzError("Got unexpected class implementing Type: " + genericType);
    }
  }

  public Object autofuzz(FuzzedDataProvider data, Method method) {
    return autofuzz(data, method, null);
  }

  // Renamed so that it doesn't clash with the static method consume, which we don't want to rename
  // as the api package depends on it by name.
  public Object consumeNonStatic(FuzzedDataProvider data, Class<?> type) {
    return consume(data, type, null);
  }

  Object autofuzz(FuzzedDataProvider data, Method method, AutofuzzCodegenVisitor visitor) {
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
        // Since the this object can be a complex expression, wrap it in parenthesis.
        visitor.pushGroup("(", ").", "");
      }
      try {
        Object thisObject = consume(data, method.getDeclaringClass(), visitor);
        if (thisObject == null) {
          throw new AutofuzzConstructionException();
        }
        result = autofuzz(data, method, thisObject, visitor);
      } finally {
        if (visitor != null) {
          visitor.popGroup();
        }
      }
    }
    return result;
  }

  public Object autofuzz(FuzzedDataProvider data, Method method, Object thisObject) {
    return autofuzz(data, method, thisObject, null);
  }

  Object autofuzz(
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
      if (e.getCause() instanceof HardToCatchError) {
        throw new AutofuzzInvocationException();
      }
      throw new AutofuzzInvocationException(e.getCause());
    }
  }

  Object autofuzzForConsume(
      FuzzedDataProvider data, Constructor<?> constructor, AutofuzzCodegenVisitor visitor) {
    try {
      return autofuzz(data, constructor, visitor);
    } catch (AutofuzzConstructionException e) {
      // Do not nest AutofuzzConstructionExceptions.
      throw e;
    } catch (AutofuzzInvocationException e) {
      // If an invocation fails during consume and thus while trying to construct a valid object,
      // the exception should not be reported as a finding, so we rewrap it.
      throw new AutofuzzConstructionException(e.getCause());
    } catch (Throwable t) {
      throw new AutofuzzConstructionException(t);
    }
  }

  Object autofuzzForConsume(
      FuzzedDataProvider data, Method method, Object thisObject, AutofuzzCodegenVisitor visitor) {
    try {
      return autofuzz(data, method, thisObject, visitor);
    } catch (AutofuzzConstructionException e) {
      // Do not nest AutofuzzConstructionExceptions.
      throw e;
    } catch (AutofuzzInvocationException e) {
      // If an invocation fails during consume and thus while trying to construct a valid object,
      // the exception should not be reported as a finding, so we rewrap it.
      throw new AutofuzzConstructionException(e.getCause());
    } catch (Throwable t) {
      throw new AutofuzzConstructionException(t);
    }
  }

  public <R> R autofuzz(FuzzedDataProvider data, Constructor<R> constructor) {
    return autofuzz(data, constructor, null);
  }

  <R> R autofuzz(
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
      if (e.getCause() instanceof HardToCatchError) {
        throw new AutofuzzInvocationException();
      }
      throw new AutofuzzInvocationException(e.getCause());
    }
  }

  // Invariant: The Java source code representation of the returned object visited by visitor must
  // represent an object of the same type as genericType. For example, a null value returned for
  // the genericType Class<java.lang.String> should lead to the generated code
  // "(java.lang.String) null", not just "null". This makes it possible to safely use consume in
  // recursive argument constructions.
  // Exception: Some Java libraries offer public methods that take private interfaces or abstract
  // classes as parameters. In this case, a cast to the parent type would cause an
  // IllegalAccessError. Since this case should be rare and there is no good alternative to
  // disambiguate overloads, we omit the cast in this case.
  Object consume(FuzzedDataProvider data, Type genericType, AutofuzzCodegenVisitor visitor) {
    Class<?> type = getRawType(genericType);
    if (type == byte.class || type == Byte.class) {
      byte result = data.consumeByte();
      if (visitor != null) {
        visitor.pushElement(String.format("(byte) %s", result));
      }
      return result;
    } else if (type == short.class || type == Short.class) {
      short result = data.consumeShort();
      if (visitor != null) {
        visitor.pushElement(String.format("(short) %s", result));
      }
      return result;
    } else if (type == int.class || type == Integer.class) {
      int result = data.consumeInt();
      if (visitor != null) {
        visitor.pushElement(Integer.toString(result));
      }
      return result;
    } else if (type == long.class || type == Long.class) {
      long result = data.consumeLong();
      if (visitor != null) {
        visitor.pushElement(String.format("%sL", result));
      }
      return result;
    } else if (type == float.class || type == Float.class) {
      float result = data.consumeFloat();
      if (visitor != null) {
        visitor.pushElement(String.format("%sF", result));
      }
      return result;
    } else if (type == double.class || type == Double.class) {
      double result = data.consumeDouble();
      if (visitor != null) {
        visitor.pushElement(Double.toString(result));
      }
      return result;
    } else if (type == boolean.class || type == Boolean.class) {
      boolean result = data.consumeBoolean();
      if (visitor != null) {
        visitor.pushElement(Boolean.toString(result));
      }
      return result;
    } else if (type == char.class || type == Character.class) {
      char result = data.consumeChar();
      if (visitor != null) {
        visitor.addCharLiteral(result);
      }
      return result;
    }
    // Sometimes, but rarely return null for non-primitive and non-boxed types.
    // TODO: We might want to return null for boxed types sometimes, but this is complicated by the
    //       fact that TypeUtils can't distinguish between a primitive type and its wrapper and may
    //       thus easily cause false-positive NullPointerExceptions.
    if (!type.isPrimitive() && data.consumeByte() == 0) {
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
      if (visitor != null) {
        visitor.addStringLiteral(result);
      }
      return result;
    } else if (type.isArray()) {
      if (type == byte[].class) {
        byte[] result = data.consumeBytes(consumeArrayLength(data, Byte.BYTES));
        if (visitor != null) {
          visitor.pushElement(
              IntStream.range(0, result.length)
                  .mapToObj(i -> "(byte) " + result[i])
                  .collect(Collectors.joining(", ", "new byte[]{", "}")));
        }
        return result;
      } else if (type == int[].class) {
        int[] result = data.consumeInts(consumeArrayLength(data, Integer.BYTES));
        if (visitor != null) {
          visitor.pushElement(
              Arrays.stream(result)
                  .mapToObj(String::valueOf)
                  .collect(Collectors.joining(", ", "new int[]{", "}")));
        }
        return result;
      } else if (type == short[].class) {
        short[] result = data.consumeShorts(consumeArrayLength(data, Short.BYTES));
        if (visitor != null) {
          visitor.pushElement(
              IntStream.range(0, result.length)
                  .mapToObj(i -> "(short) " + result[i])
                  .collect(Collectors.joining(", ", "new short[]{", "}")));
        }
        return result;
      } else if (type == long[].class) {
        long[] result = data.consumeLongs(consumeArrayLength(data, Long.BYTES));
        if (visitor != null) {
          visitor.pushElement(
              Arrays.stream(result)
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
        Object array =
            Array.newInstance(
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
        visitor.pushElement(
            IntStream.range(0, array.length)
                .mapToObj(i -> "(byte) " + array[i])
                .collect(
                    Collectors.joining(
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
            String.format(
                "java.util.stream.Stream.<java.util.AbstractMap.SimpleEntry<%s, %s>>of(",
                keyType.getTypeName(), valueType.getTypeName()),
            ", ",
            ").collect(java.util.HashMap::new, (map, e) -> map.put(e.getKey(), e.getValue()),"
                + " java.util.HashMap::putAll)");
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
      if (visitor != null) {
        visitor.pushElement(String.format("%s.class", YourAverageJavaClass.class.getName()));
      }
      return YourAverageJavaClass.class;
    } else if (type == Method.class) {
      if (visitor != null) {
        throw new AutofuzzError("codegen has not been implemented for Method.class");
      }
      return data.pickValue(lookup.getAccessibleMethods(YourAverageJavaClass.class));
    } else if (type == Constructor.class) {
      if (visitor != null) {
        throw new AutofuzzError("codegen has not been implemented for Constructor.class");
      }
      return data.pickValue(lookup.getAccessibleConstructors(YourAverageJavaClass.class));
    } else if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
      List<Class<?>> implementingClasses = implementingClassesCache.get(type);
      if (implementingClasses == null) {
        // TODO: We may be scanning multiple times. Instead, we should keep the ScanResult around
        //  for as long as there is enough memory.
        ClassGraph classGraph =
            new ClassGraph()
                .enableClassInfo()
                .ignoreClassVisibility()
                .ignoreMethodVisibility()
                .enableInterClassDependencies()
                .rejectPackages("jaz");
        if (!IS_TEST) {
          classGraph.rejectPackages("com.code_intelligence.jazzer");
        }
        try (ScanResult result = classGraph.scan()) {
          ClassInfoList children =
              type.isInterface() ? result.getClassesImplementing(type) : result.getSubclasses(type);
          implementingClasses =
              children
                  .getStandardClasses()
                  .filter(info -> !Modifier.isAbstract(info.getModifiers()))
                  .filter(info -> lookup.isAccessible(info, info.getModifiers()))
                  // Filter out anonymous and local classes, which can't be
                  // instantiated in reproducers.
                  .filter(info -> info.getName() != null)
                  .loadClasses();
          implementingClassesCache.put(type, implementingClasses);
        }
      }
      if (implementingClasses.isEmpty()) {
        if (IS_DEBUG) {
          throw new AutofuzzConstructionException(
              String.format(
                  "Could not find classes implementing %s on the classpath", type.getName()));
        } else {
          throw new AutofuzzConstructionException();
        }
      }
      if (visitor != null) {
        // See the "Exception" note in the method comment.
        if (Modifier.isPublic(type.getModifiers())) {
          // This group will always have a single element: The instance of the implementing class.
          visitor.pushGroup(String.format("(%s) ", type.getCanonicalName()), "", "");
        }
      }
      Object result = consume(data, data.pickValue(implementingClasses), visitor);
      if (visitor != null) {
        if (Modifier.isPublic(type.getModifiers())) {
          visitor.popGroup();
        }
      }
      return result;
    }
    Constructor<?>[] constructors = lookup.getAccessibleConstructors(type);
    if (constructors.length > 0) {
      Constructor<?> constructor = data.pickValue(constructors);
      boolean applySetters = constructor.getParameterCount() == 0;
      if (visitor != null && applySetters) {
        // Embed the instance creation and setters into an immediately invoked lambda expression to
        // turn them into an expression.
        String uniqueVariableName = visitor.uniqueVariableName();
        visitor.pushGroup(
            String.format(
                "((java.util.function.Supplier<%1$s>) (() -> {%1$s %2$s = ",
                type.getCanonicalName(), uniqueVariableName),
            String.format("; %s.", uniqueVariableName),
            String.format("; return %s;})).get()", uniqueVariableName));
      }
      Object obj = autofuzzForConsume(data, constructor, visitor);
      if (applySetters) {
        List<Method> potentialSetters = getPotentialSetters(type);
        if (!potentialSetters.isEmpty()) {
          List<Method> pickedSetters =
              data.pickValues(potentialSetters, data.consumeInt(0, potentialSetters.size()));
          for (Method setter : pickedSetters) {
            autofuzzForConsume(data, setter, obj, visitor);
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
          autofuzzForConsume(
              data, data.pickValue(lookup.getAccessibleConstructors(pickedBuilder)), visitor);
      for (Method method : pickedMethods) {
        builderObj = autofuzzForConsume(data, method, builderObj, visitor);
      }

      try {
        Object obj = autofuzzForConsume(data, builderMethod, builderObj, visitor);
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
    if (IS_DEBUG) {
      String summary =
          String.format(
              "Failed to generate instance of %s:%nAccessible constructors: %s%nNested subclasses:"
                  + " %s%n",
              type.getName(),
              Arrays.stream(lookup.getAccessibleConstructors(type))
                  .map(Utils::getReadableDescriptor)
                  .collect(Collectors.joining(", ")),
              Arrays.stream(lookup.getAccessibleClasses(type))
                  .map(Class::getName)
                  .collect(Collectors.joining(", ")));
      throw new AutofuzzConstructionException(summary);
    } else {
      throw new AutofuzzConstructionException();
    }
  }

  private List<Class<?>> getNestedBuilderClasses(Class<?> type) {
    List<Class<?>> nestedBuilderClasses = nestedBuilderClassesCache.get(type);
    if (nestedBuilderClasses == null) {
      nestedBuilderClasses =
          Arrays.stream(lookup.getAccessibleClasses(type))
              .filter(cls -> cls.getName().endsWith("Builder"))
              .filter(cls -> !getOriginalObjectCreationMethods(cls).isEmpty())
              .collect(Collectors.toList());
      nestedBuilderClassesCache.put(type, nestedBuilderClasses);
    }
    return nestedBuilderClasses;
  }

  private List<Method> getOriginalObjectCreationMethods(Class<?> builder) {
    List<Method> originalObjectCreationMethods = originalObjectCreationMethodsCache.get(builder);
    if (originalObjectCreationMethods == null) {
      originalObjectCreationMethods =
          Arrays.stream(lookup.getAccessibleMethods(builder))
              .filter(m -> m.getReturnType() == builder.getEnclosingClass())
              .collect(Collectors.toList());
      originalObjectCreationMethodsCache.put(builder, originalObjectCreationMethods);
    }
    return originalObjectCreationMethods;
  }

  private List<Method> getCascadingBuilderMethods(Class<?> builder) {
    List<Method> cascadingBuilderMethods = cascadingBuilderMethodsCache.get(builder);
    if (cascadingBuilderMethods == null) {
      cascadingBuilderMethods =
          Arrays.stream(lookup.getAccessibleMethods(builder))
              .filter(m -> m.getReturnType() == builder)
              .collect(Collectors.toList());
      cascadingBuilderMethodsCache.put(builder, cascadingBuilderMethods);
    }
    return cascadingBuilderMethods;
  }

  private List<Method> getPotentialSetters(Class<?> type) {
    return Arrays.stream(lookup.getAccessibleMethods(type))
        .filter(method -> void.class.equals(method.getReturnType()))
        .filter(method -> method.getParameterCount() == 1)
        .filter(method -> method.getName().startsWith("set"))
        .collect(Collectors.toList());
  }

  public Object[] consumeArguments(
      FuzzedDataProvider data, Executable executable, AutofuzzCodegenVisitor visitor) {
    Object[] result;
    try {
      result =
          Arrays.stream(executable.getGenericParameterTypes())
              .map(type -> consume(data, type, visitor))
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

  private Object consumeChecked(FuzzedDataProvider data, Class<?>[] types, int i) {
    if (types[i] == Unknown.class) {
      throw new AutofuzzError("Failed to determine type of argument " + (i + 1));
    }
    Object result;
    try {
      result = consumeNonStatic(data, types[i]);
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
}
