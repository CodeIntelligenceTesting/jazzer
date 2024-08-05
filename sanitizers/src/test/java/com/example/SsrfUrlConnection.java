/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
