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
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.CountDownLatch;

public class SsrfAllowUntilConfigured {

  private static final CountDownLatch fuzzTestStarted = new CountDownLatch(1);

  static {
    // Simulate a background thread that starts before fuzz test configuration
    Thread backgroundThread =
        new Thread(
            () -> {
              try {
                // Wait for fuzz test to start but before it configures SSRF
                fuzzTestStarted.await();
                System.out.println("Background thread making early request...");

                URL url = new URL("https://localhost:8080");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(1000);
                conn.setReadTimeout(1000);
                conn.getResponseCode();
                conn.disconnect();
              } catch (Exception ignored) {
              }
            });
    backgroundThread.setDaemon(true);
    backgroundThread.start();
  }

  public static void fuzzerTestOneInput(boolean ignored) throws Exception {
    fuzzTestStarted.countDown();
    Thread.sleep(500); // Ensure background thread has time to run

    BugDetectors.allowNetworkConnections((host, port) -> host.equals("localhost"));
  }
}
