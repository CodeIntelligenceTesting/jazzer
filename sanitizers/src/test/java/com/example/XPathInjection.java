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
import java.io.*;
import javax.xml.parsers.*;
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import org.xml.sax.*;

public class XPathInjection {
  static Document doc = null;
  static XPath xpath = null;

  public static void fuzzerInitialize() throws Exception {
    String xmlFile = "<user name=\"user\" pass=\"pass\"></user>";

    DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
    domFactory.setNamespaceAware(true);
    DocumentBuilder builder = domFactory.newDocumentBuilder();
    doc = builder.parse(new InputSource(new StringReader(xmlFile)));

    XPathFactory xpathFactory = XPathFactory.newInstance();
    xpath = xpathFactory.newXPath();
  }

  public static void unsafeEval(String user, String pass) {
    if (user != null && pass != null) {
      String expression = "/user[@name='" + user + "' and @pass='" + pass + "']";
      try {
        xpath.evaluate(expression, doc, XPathConstants.BOOLEAN);
      } catch (XPathExpressionException e) {
      }
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    unsafeEval(data.consumeString(20), data.consumeRemainingAsString());
  }
}
