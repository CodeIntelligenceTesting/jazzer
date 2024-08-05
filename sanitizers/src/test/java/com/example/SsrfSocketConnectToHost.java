/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.BugDetectors;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class SsrfSocketConnectToHost {
  // We don't actually care about establishing a connection and thus choose the lowest possible
  // timeout.
  private static final int CONNECTION_TIMEOUT_MS = 1;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    String host = data.consumeAsciiString(15);
    int port = data.consumeInt(1, 65535);

    try (AutoCloseable ignored = BugDetectors.allowNetworkConnections()) {
      // Verify that policies nest properly.
      try (AutoCloseable ignored1 =
          BugDetectors.allowNetworkConnections((String h, Integer p) -> h.equals("localhost"))) {
        try (AutoCloseable ignored2 = BugDetectors.allowNetworkConnections()) {}
        try (Socket s = new Socket()) {
          s.connect(new InetSocketAddress(host, port), CONNECTION_TIMEOUT_MS);
        } catch (IOException ignored3) {
        }
      }
    }
  }
}
