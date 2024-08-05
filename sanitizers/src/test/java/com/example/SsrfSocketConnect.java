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
import java.net.Socket;

public class SsrfSocketConnect {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    String hostname = data.consumeString(15);
    try (Socket s = new Socket(hostname, 80)) {
      s.getInetAddress();
    }
  }
}
