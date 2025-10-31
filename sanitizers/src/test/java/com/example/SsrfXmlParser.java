/*
 * Copyright 2025 Code Intelligence GmbH
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

import java.io.StringReader;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

public class SsrfXmlParser {

  public static void fuzzerTestOneInput(byte[] data) throws Exception {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    // Default XML parser supports looking up external entities.
    // Disallow all doctype declarations if XML is not trusted:
    //    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    XMLReader parser = factory.newSAXParser().getXMLReader();
    parser.setErrorHandler(new DefaultHandler() {});
    try {
      parser.parse(new InputSource(new StringReader(new String(data))));
    } catch (Exception ignored) {
    }
  }
}
