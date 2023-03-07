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

package com.code_intelligence.jazzer.sanitizers;

import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import com.code_intelligence.jazzer.api.MethodHooks;
import java.io.IOException;
import java.io.Reader;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Stream;
import javax.script.ScriptEngineManager;

/**
 * Detects Script Engine injection
 *
 * <p>
 * The hooks in this class attempt to detect user input flowing into
 * {@link javax.script.ScriptEngine.eval} that might lead to
 * remote code executions depending on the scripting engine's capabilities.
 * Before JDK 15, the Nashorn Engine
 * was registered by default with ScriptEngineManager under several aliases,
 * including "js". Nashorn allows
 * access to JVM classes, for example {@link java.lang.Runtime} allowing the
 * execution of arbitrary OS commands.
 * Several other scripting engines can be embedded to the JVM (they must follow
 * the <a href="https://www.jcp.org/en/jsr/detail?id=223">JSR-223</a>
 * specification).
 * </p>
 **/
public final class ScriptEngineInjection {
  private static final String ENGINE = "js";
  private static final String PAYLOAD = "1+1";

  private static char[] guideMarkableReaderTowardsEquality(Reader reader, String target, int id)
      throws IOException {
    final int size = target.length();
    char[] current = new char[size];
    int n = 0;

    if (!reader.markSupported()) {
      throw new IllegalStateException("Reader does not support mark - not possible to fuzz");
    }

    reader.mark(size);

    while (n < size) {
      int count = reader.read(current, n, size - n);
      if (count < 0)
        break;
      n += count;
    }
    reader.reset();

    Jazzer.guideTowardsEquality(new String(current), target, id);

    return current;
  }

  @MethodHook(type = HookType.REPLACE, targetClassName = "javax.script.ScriptEngineManager",
      targetMethod = "registerEngineName")
  public static Object
  ensureScriptEngine(MethodHandle method, Object thisObject, Object[] arguments, int hookId)
      throws Throwable {
    return method.invokeWithArguments(Stream
                                          .concat(Stream.of(thisObject),
                                              Stream.concat(Stream.of((Object) ENGINE),
                                                  Arrays.stream(arguments, 1, arguments.length)))
                                          .toArray());
  }

  @MethodHook(type = HookType.REPLACE, targetClassName = "javax.script.ScriptEngineManager",
      targetMethod = "getEngineByName",
      targetMethodDescriptor = "(Ljava/lang/String;)Ljavax/script/ScriptEngine;")
  public static Object
  hookEngineName(MethodHandle method, Object thisObject, Object[] arguments, int hookId)
      throws Throwable {
    String engine = (String) arguments[0];
    Jazzer.guideTowardsEquality(engine, ENGINE, hookId);
    return method.invokeWithArguments(
        Stream.concat(Stream.of(thisObject), Arrays.stream(arguments)).toArray());
  }

  @MethodHook(type = HookType.BEFORE, targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval", targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/Object;")
  @MethodHook(type = HookType.BEFORE, targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval", targetMethodDescriptor = "(Ljava/io/Reader;)Ljava/lang/Object;")
  public static void
  checkScriptEngineExecute(MethodHandle method, Object thisObject, Object[] arguments, int hookId)
      throws Throwable {
    String script = null;

    if (arguments[0] instanceof String) {
      script = (String) arguments[0];
      Jazzer.guideTowardsEquality(script, PAYLOAD, hookId);
    } else {
      script =
          new String(guideMarkableReaderTowardsEquality((Reader) arguments[0], PAYLOAD, hookId));
    }

    if (script.equals(PAYLOAD)) {
      Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical("Possible script execution"));
    }
  }
}
