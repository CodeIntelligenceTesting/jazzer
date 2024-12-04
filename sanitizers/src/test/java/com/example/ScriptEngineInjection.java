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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.util.List;
import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;

public class ScriptEngineInjection {
  private static final ScriptEngine engine = new DummyScriptEngine();
  private static final ScriptContext context = new DummyScriptContext();

  private static void insecureScriptEval(String input) throws Exception {
    engine.eval(new StringReader(input), context);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      insecureScriptEval(data.consumeRemainingAsAsciiString());
    } catch (Exception ignored) {
    }
  }

  private static class DummyScriptEngine implements ScriptEngine {
    @Override
    public Bindings createBindings() {
      return null;
    }

    @Override
    public Object eval(String script) {
      return null;
    }

    @Override
    public Object eval(Reader reader) {
      return null;
    }

    @Override
    public Object eval(String script, ScriptContext context) {
      return null;
    }

    @Override
    public Object eval(Reader reader, ScriptContext context) {
      return null;
    }

    @Override
    public Object eval(String script, Bindings n) {
      return null;
    }

    @Override
    public Object eval(Reader reader, Bindings n) {
      return null;
    }

    @Override
    public Object get(String key) {
      return null;
    }

    @Override
    public Bindings getBindings(int scope) {
      return null;
    }

    @Override
    public ScriptContext getContext() {
      return null;
    }

    @Override
    public ScriptEngineFactory getFactory() {
      return null;
    }

    @Override
    public void put(String key, Object value) {}

    @Override
    public void setBindings(Bindings bindings, int scope) {}

    @Override
    public void setContext(ScriptContext context) {}

    public DummyScriptEngine() {}
  }

  private static class DummyScriptContext implements ScriptContext {
    @Override
    public void setBindings(Bindings bindings, int scope) {}

    @Override
    public Bindings getBindings(int scope) {
      return null;
    }

    @Override
    public void setAttribute(String name, Object value, int scope) {}

    @Override
    public Object getAttribute(String name, int scope) {
      return null;
    }

    @Override
    public Object removeAttribute(String name, int scope) {
      return null;
    }

    @Override
    public Object getAttribute(String name) {
      return null;
    }

    @Override
    public int getAttributesScope(String name) {
      return 0;
    }

    @Override
    public Writer getWriter() {
      return null;
    }

    @Override
    public Writer getErrorWriter() {
      return null;
    }

    @Override
    public void setWriter(Writer writer) {}

    @Override
    public void setErrorWriter(Writer writer) {}

    @Override
    public Reader getReader() {
      return null;
    }

    @Override
    public void setReader(Reader reader) {}

    @Override
    public List<Integer> getScopes() {
      return null;
    }
  }
}
