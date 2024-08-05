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
