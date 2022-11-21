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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;

import java.io.Reader;
import java.io.StringReader;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

class DummyScriptEngine implements ScriptEngine {
  @Override
  public Bindings createBindings() {
    return null;
  }

  @Override
  public Object eval(String script) throws ScriptException {
    return null;
  }

  @Override
  public Object eval(Reader reader) throws ScriptException {
    return null;
  }

  @Override
  public Object eval(String script, ScriptContext context) throws ScriptException {
    return null;
  }

  @Override
  public Object eval(Reader reader, ScriptContext context) throws ScriptException {
    return null;
  }

  @Override
  public Object eval(String script, Bindings n) throws ScriptException {
    return null;
  }

  @Override
  public Object eval(Reader reader, Bindings n) throws ScriptException {
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
  public void put(String key, Object value) {
  }

  @Override
  public void setBindings(Bindings bindings, int scope) {
  }

  @Override
  public void setContext(ScriptContext context) {
  }

  public DummyScriptEngine() {
  }
}

public class ScriptEngineInjection {
  static ScriptEngine engine = new DummyScriptEngine();

  static void insecureScriptEval(String input) throws Exception {
    engine.eval(new StringReader(input));
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    try {
      insecureScriptEval(data.consumeRemainingAsAsciiString());
    } catch (Throwable t) {
      if (t instanceof FuzzerSecurityIssueCritical) {
        throw t;
      }
    }
  }
}
