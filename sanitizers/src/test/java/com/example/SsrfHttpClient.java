// Copyright 2023 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class SsrfHttpClient {
  private static final HttpClient CLIENT =
      HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    // Does not check if the fuzzer is guided correctly, only if the hook is invoked correctly.
    // Opening actual connections takes far too long.
    String hostname = data.consumeString(15);
    if ("jazzer.invalid".equals(hostname)) {
      HttpRequest request =
          HttpRequest.newBuilder().uri(URI.create("https://" + hostname)).GET().build();
      CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    }
  }
}
