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
import java.io.File;
import java.io.IOException;

public class ExamplePathTraversalFuzzer {
  /** The root path for all files that this application is allowed to upload. */
  public static final String publicFilesRootPath = "/app/upload/";

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String relativePath = data.consumeRemainingAsAsciiString();
    // Upload the file and try very hard to ignore errors thrown during the upload.
    try {
      uploadFile(relativePath);
    } catch (Throwable ignored) {
    }
  }

  private static void uploadFile(String relativePathToFile) throws IOException {
    File fileToUpload = new File(publicFilesRootPath + relativePathToFile);
    if (!fileToUpload.exists()) {
      throw new IOException("File not found");
    }
    // In a real application, the file would be uploaded to a public server here.
  }
}
