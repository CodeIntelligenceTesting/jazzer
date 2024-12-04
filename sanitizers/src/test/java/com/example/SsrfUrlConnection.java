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
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class SsrfUrlConnection {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    String hostname = data.consumeString(15);
    try {
      URL url = new URL("https://" + hostname);
      HttpURLConnection con = (HttpURLConnection) url.openConnection();
      con.setRequestMethod("GET");
      con.getInputStream();
    } catch (IOException | IllegalArgumentException ignored) {
    }
  }
}
