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
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class SsrfHttpClient {
  private static final HttpClient CLIENT =
      HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

  public static void fuzzerTestOneInput(FuzzedDataProvider data)
      throws IOException, InterruptedException {
    String hostname = data.consumeString(15);
    URI uri;
    try {
      uri = URI.create("https://" + hostname);
      HttpRequest request = HttpRequest.newBuilder().uri(uri).GET().build();
      CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (IllegalArgumentException ignored) {
    }
  }
}
