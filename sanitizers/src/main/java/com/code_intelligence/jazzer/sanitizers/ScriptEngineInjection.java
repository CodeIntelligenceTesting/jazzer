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

package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.lang.invoke.MethodHandle;

/**
 * Detects Script Engine injections.
 *
 * <p>The hooks in this class attempt to detect user input flowing into {@link
 * javax.script.ScriptEngine#eval(String)} and the like that might lead to remote code executions
 * depending on the scripting engine's capabilities. Before JDK 15, the Nashorn Engine was
 * registered by default with ScriptEngineManager under several aliases, including "js". Nashorn
 * allows access to JVM classes, for example {@link java.lang.Runtime} allowing the execution of
 * arbitrary OS commands. Several other scripting engines can be embedded to the JVM (they must
 * follow the <a href="https://www.jcp.org/en/jsr/detail?id=223">JSR-223 </a> specification).
 */
@SuppressWarnings("unused")
public final class ScriptEngineInjection {
  private static final String PAYLOAD = "\"jaz\"+\"zer\"";

  /**
   * String variants of eval can be intercepted by before hooks, as the script content can directly
   * be checked for the presence of the payload.
   */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval",
      targetMethodDescriptor = "(Ljava/lang/String;)Ljava/lang/Object;")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval",
      targetMethodDescriptor = "(Ljava/lang/String;Ljavax/script/ScriptContext;)Ljava/lang/Object;")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval",
      targetMethodDescriptor = "(Ljava/lang/String;Ljavax/script/Bindings;)Ljava/lang/Object;")
  public static void checkScriptEngineExecuteString(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkScriptContent((String) arguments[0], hookId);
  }

  /**
   * Reader variants of eval must be intercepted by replace hooks, as their contents are converted
   * to strings, for the payload check, and back to readers for the actual method invocation.
   */
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval",
      targetMethodDescriptor = "(Ljava/io/Reader;)Ljava/lang/Object;")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval",
      targetMethodDescriptor = "(Ljava/io/Reader;Ljavax/script/ScriptContext;)Ljava/lang/Object;")
  @MethodHook(
      type = HookType.REPLACE,
      targetClassName = "javax.script.ScriptEngine",
      targetMethod = "eval",
      targetMethodDescriptor = "(Ljava/io/Reader;Ljavax/script/Bindings;)Ljava/lang/Object;")
  public static Object checkScriptEngineExecute(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
    if (arguments[0] != null) {
      String content = readAll((Reader) arguments[0]);
      checkScriptContent(content, hookId);
      arguments[0] = new StringReader(content);
    }
    return method.invokeWithArguments(thisObject, arguments);
  }

  private static void checkScriptContent(String content, int hookId) {
    if (content != null) {
      if (content.contains(PAYLOAD)) {
        Jazzer.reportFindingFromHook(
            new FuzzerSecurityIssueCritical(
                "Script Engine Injection: Insecure user input was used in script engine"
                    + " invocation.\n"
                    + "Depending on the script engine's capabilities this could lead to sandbox"
                    + " escape and remote code execution."));
      } else {
        Jazzer.guideTowardsContainment(content, PAYLOAD, hookId);
      }
    }
  }

  private static String readAll(Reader reader) throws IOException {
    StringBuilder content = new StringBuilder();
    char[] buffer = new char[4096];
    int numChars;
    while ((numChars = reader.read(buffer)) >= 0) {
      content.append(buffer, 0, numChars);
    }
    return content.toString();
  }
}
