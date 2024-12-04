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
