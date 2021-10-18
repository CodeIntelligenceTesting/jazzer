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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.utils.Utils;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfoList;
import io.github.classgraph.ScanResult;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Collectors;
import net.jodah.typetools.TypeResolver;
import net.jodah.typetools.TypeResolver.Unknown;

public class Meta {
  static WeakHashMap<Class<?>, List<Class<?>>> implementingClassesCache = new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Class<?>>> nestedBuilderClassesCache = new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Method>> originalObjectCreationMethodsCache =
      new WeakHashMap<>();

  public static Object autofuzz(FuzzedDataProvider data, Method method) {
    if (Modifier.isStatic(method.getModifiers())) {
      return autofuzz(data, method, null);
    } else {
      Object thisObject = consume(data, method.getDeclaringClass());
      if (thisObject == null) {
        throw new AutofuzzConstructionException();
      }
      return autofuzz(data, method, thisObject);
    }
  }

  public static Object autofuzz(FuzzedDataProvider data, Method method, Object thisObject) {
    Object[] arguments = consumeArguments(data, method);
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
    Object[] arguments = consumeArguments(data, constructor);
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
  public static <T1, R> R autofuzz(FuzzedDataProvider data, Function1<T1, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function1.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, R> R autofuzz(FuzzedDataProvider data, Function2<T1, T2, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function2.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1));
  }

  public static Object consume(FuzzedDataProvider data, Class<?> type) {
    if (type == byte.class || type == Byte.class) {
      return data.consumeByte();
    } else if (type == short.class || type == Short.class) {
      return data.consumeShort();
    } else if (type == int.class || type == Integer.class) {
      return data.consumeInt();
    } else if (type == long.class || type == Long.class) {
      return data.consumeLong();
    } else if (type == float.class || type == Float.class) {
      return data.consumeFloat();
    } else if (type == double.class || type == Double.class) {
      return data.consumeDouble();
    } else if (type == boolean.class || type == Boolean.class) {
      return data.consumeBoolean();
    } else if (type == char.class || type == Character.class) {
      return data.consumeChar();
    }
    // Return null for non-primitive and non-boxed types in ~5% of the cases.
    // TODO: We might want to return null for boxed types sometimes, but this is complicated by the
    //       fact that TypeUtils can't distinguish between a primitive type and its wrapper and may
    //       thus easily cause false-positive NullPointerExceptions.
    if (!type.isPrimitive() && data.consumeByte((byte) 0, (byte) 19) == 0) {
      return null;
    }
    if (type.isAssignableFrom(String.class)) {
      return data.consumeString(data.remainingBytes() / 2);
    } else if (type.isArray()) {
      if (type == byte[].class) {
        return data.consumeBytes(data.remainingBytes() / 2);
      } else if (type == int[].class) {
        return data.consumeInts(data.remainingBytes() / 2);
      } else if (type == short[].class) {
        return data.consumeShorts(data.remainingBytes() / 2);
      } else if (type == long[].class) {
        return data.consumeLongs(data.remainingBytes() / 2);
      } else if (type == boolean[].class) {
        return data.consumeBooleans(data.remainingBytes() / 2);
      } else {
        Object array = Array.newInstance(type.getComponentType(), data.remainingBytes() / 2);
        for (int i = 0; i < Array.getLength(array); i++) {
          Array.set(array, i, consume(data, type.getComponentType()));
        }
        return array;
      }
    } else if (type.isAssignableFrom(ByteArrayInputStream.class)) {
      return new ByteArrayInputStream(data.consumeBytes(data.remainingBytes() / 2));
    } else if (type.isEnum()) {
      return data.pickValue(type.getEnumConstants());
    } else if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
      List<Class<?>> implementingClasses = implementingClassesCache.get(type);
      if (implementingClasses == null) {
        try (ScanResult result =
                 new ClassGraph().enableClassInfo().enableInterClassDependencies().scan()) {
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
      return consume(data, data.pickValue(implementingClasses));
    } else if (type.getConstructors().length > 0) {
      Constructor<?> constructor = data.pickValue(type.getConstructors());
      Object obj = autofuzz(data, constructor);
      if (constructor.getParameterCount() == 0) {
        List<Method> potentialSetters = getPotentialSetters(type);
        if (!potentialSetters.isEmpty()) {
          List<Method> pickedSetters =
              data.pickValues(potentialSetters, data.consumeInt(0, potentialSetters.size()));
          for (Method setter : pickedSetters) {
            autofuzz(data, setter, obj);
          }
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

      List<Method> cascadingBuilderMethods = Arrays.stream(pickedBuilder.getMethods())
                                                 .filter(m -> m.getReturnType() == pickedBuilder)
                                                 .collect(Collectors.toList());

      List<Method> originalObjectCreationMethods = getOriginalObjectCreationMethods(pickedBuilder);

      int pickedMethodsNumber = data.consumeInt(0, cascadingBuilderMethods.size());
      List<Method> pickedMethods = data.pickValues(cascadingBuilderMethods, pickedMethodsNumber);

      Method builderMethod = data.pickValue(originalObjectCreationMethods);

      Object builderObj = autofuzz(data, data.pickValue(pickedBuilder.getConstructors()));
      for (Method method : pickedMethods) {
        builderObj = autofuzz(data, method, builderObj);
      }

      try {
        return builderMethod.invoke(builderObj);
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

  static boolean isDebug() {
    String value = System.getenv("JAZZER_AUTOFUZZ_DEBUG");
    return value != null && !value.isEmpty();
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

  private static List<Class<?>> getNestedBuilderClasses(Class<?> type) {
    List<Class<?>> nestedBuilderClasses = nestedBuilderClassesCache.get(type);
    if (nestedBuilderClasses == null) {
      nestedBuilderClasses = Arrays.stream(type.getClasses())
                                 .filter(cls -> cls.getName().endsWith("Builder"))
                                 .filter(cls -> !getOriginalObjectCreationMethods(cls).isEmpty())
                                 .collect(Collectors.toList());
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
      originalObjectCreationMethodsCache.put(builder, originalObjectCreationMethods);
    }
    return originalObjectCreationMethods;
  }

  private static List<Method> getPotentialSetters(Class<?> type) {
    List<Method> potentialSetters = new ArrayList<>();
    List<Method> methods = Arrays.asList(type.getMethods());
    methods.sort(Comparator.comparing(Method::getName));
    for (Method method : methods) {
      if (void.class.equals(method.getReturnType()) && method.getParameterCount() == 1
          && method.getName().startsWith("set")) {
        potentialSetters.add(method);
      }
    }
    return potentialSetters;
  }

  private static Object[] consumeArguments(FuzzedDataProvider data, Executable executable) {
    Object[] result;
    try {
      result = Arrays.stream(executable.getParameterTypes())
                   .map((type) -> consume(data, type))
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
}
