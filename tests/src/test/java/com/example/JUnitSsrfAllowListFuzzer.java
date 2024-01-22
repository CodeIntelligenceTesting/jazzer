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
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.net.ConnectException;
import java.net.Socket;

public class JUnitSsrfAllowListFuzzer {

  @FuzzTest
  void fuzzTest(FuzzedDataProvider data) throws Exception {
    BugDetectors.allowNetworkConnections(
        (host, port) -> host.equals("localhost") && port.equals(62351));
    try (Socket s = new Socket("localhost", 62351)) {
      s.getInetAddress();
    } catch (ConnectException ignored) {
    }
  }
}
