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
import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import net.jodah.typetools.TypeResolver;
import net.jodah.typetools.TypeResolver.Unknown;

public class Meta {
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
    } else if (type.isAssignableFrom(String.class)) {
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
    } else if (Modifier.isAbstract(type.getModifiers())) {
    } else if (type.isInterface()) {
    } else if (type.getConstructors().length > 0) {
      return autofuzz(data, data.pickValue(type.getConstructors()));
    }
    return null;
  }

  private static Object consumeChecked(FuzzedDataProvider data, Class<?>[] types, int i) {
    if (types[i] == Unknown.class) {
      throw new IllegalArgumentException("Failed to determine type of argument " + (i + 1));
    }
    Object result = consume(data, types[i]);
    if (result != null && !types[i].isAssignableFrom(result.getClass())) {
      throw new IllegalStateException(
          "consume returned " + result.getClass() + ", but need " + types[i]);
    }
    return result;
  }

  public static Object autofuzz(FuzzedDataProvider data, Method method) {
    if (Modifier.isStatic(method.getModifiers())) {
      return autofuzz(data, method, null);
    } else {
      return autofuzz(data, method, consume(data, method.getDeclaringClass()));
    }
  }

  public static Object autofuzz(FuzzedDataProvider data, Method method, Object thisObject) {
    Object[] arguments = consumeArguments(data, method);
    try {
      return method.invoke(thisObject, arguments);
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    } catch (InvocationTargetException e) {
      throw new RuntimeException(e.getCause());
    }
  }

  public static <R> R autofuzz(FuzzedDataProvider data, Constructor<R> constructor) {
    Object[] arguments = consumeArguments(data, constructor);
    try {
      return constructor.newInstance(arguments);
    } catch (InstantiationException | IllegalAccessException e) {
      throw new RuntimeException(e);
    } catch (InvocationTargetException e) {
      throw new RuntimeException(e.getCause());
    }
  }

  private static Object[] consumeArguments(FuzzedDataProvider data, Executable executable) {
    return Arrays.stream(executable.getParameterTypes())
        .map((type) -> consume(data, type))
        .toArray();
  }

  public static <T1> void autofuzz(FuzzedDataProvider data, Consumer1<T1> func) {
    Class<?> type = TypeResolver.resolveRawArgument(Consumer1.class, func.getClass());
    if (type == Unknown.class) {
      throw new IllegalArgumentException("Failed to determine type of argument 1");
    }
    Object result = consume(data, type);
    if (result != null && !type.isAssignableFrom(result.getClass())) {
      throw new IllegalStateException(
          "consume returned " + result.getClass() + ", but need " + type);
    }
    func.accept((T1) result);
  }

  public static <T1, R> R autofuzz(FuzzedDataProvider data, Function1<T1, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function1.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0));
  }

  public static <T1, T2, R> R autofuzz(FuzzedDataProvider data, Function2<T1, T2, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function2.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1));
  }
}
