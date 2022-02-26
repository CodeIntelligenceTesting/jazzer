// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.runtime;

import java.lang.reflect.Field;
import sun.misc.Unsafe;

public final class UnsafeProvider {
  private static final Unsafe UNSAFE = getUnsafeInternal();

  public static Unsafe getUnsafe() {
    return UNSAFE;
  }

  private static Unsafe getUnsafeInternal() {
    try {
      // The Java agent is loaded by the bootstrap class loader and should thus
      // pass the security checks in getUnsafe.
      return Unsafe.getUnsafe();
    } catch (Throwable unused) {
      // If not running as an agent, use the classical reflection trick to get an Unsafe instance,
      // taking into account that the private field may have a name other than "theUnsafe":
      // https://android.googlesource.com/platform/libcore/+/gingerbread/luni/src/main/java/sun/misc/Unsafe.java#32
      try {
        for (Field f : Unsafe.class.getDeclaredFields()) {
          if (f.getType() == Unsafe.class) {
            f.setAccessible(true);
            return (Unsafe) f.get(null);
          }
        }
        return null;
      } catch (Throwable t) {
        t.printStackTrace();
        return null;
      }
    }
  }
}
