/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import freemarker.template.Template;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

public class TemplateInjection {
  public static void fuzzerTestOneInput(FuzzedDataProvider fdp) throws Exception {
    Map<String, Object> model = new HashMap<>();
    String data = fdp.consumeRemainingAsString();
    try {
      Template tmpl = new Template("test", new StringReader(data));
      tmpl.process(model, new StringWriter());
    } catch (Throwable ignored) {
    }
  }
}
