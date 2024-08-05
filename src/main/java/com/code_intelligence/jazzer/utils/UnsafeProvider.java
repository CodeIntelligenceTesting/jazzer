/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.utils;

import java.lang.reflect.Field;
import java.util.Arrays;
import sun.misc.Unsafe;

public final class UnsafeProvider {
  private static final Unsafe UNSAFE = getUnsafeInternal();

  public static Unsafe getUnsafe() {
    return UNSAFE;
  }

  private static Unsafe getUnsafeInternal() {
    try {
      // The Jazzer runtime is loaded by the bootstrap class loader and should thus pass the
      // security checks in getUnsafe, so try that first.
      return Unsafe.getUnsafe();
    } catch (Throwable unused) {
      // If not running as an agent, use the classical reflection trick to get an Unsafe instance,
      // taking into account that the private field may have a name other than "theUnsafe":
      // https://android.googlesource.com/platform/libcore/+/gingerbread/luni/src/main/java/sun/misc/Unsafe.java#32
      for (Field f : Unsafe.class.getDeclaredFields()) {
        if (f.getType() == Unsafe.class) {
          f.setAccessible(true);
          try {
            return (Unsafe) f.get(null);
          } catch (IllegalAccessException e) {
            throw new IllegalStateException(
                "Please file a bug at https://github.com/CodeIntelligenceTesting/jazzer/issues/new "
                    + "with this information: Failed to access Unsafe member on Unsafe class",
                e);
          }
        }
      }
      throw new IllegalStateException(
          String.format(
              "Please file a bug at https://github.com/CodeIntelligenceTesting/jazzer/issues/new"
                  + " with this information: Failed to find Unsafe member on Unsafe class, have: "
                  + Arrays.deepToString(Unsafe.class.getDeclaredFields())));
    }
  }
}
