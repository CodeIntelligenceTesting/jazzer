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
import java.io.*;
import org.apache.batik.transcoder.TranscoderException;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.JPEGTranscoder;

public class BatikTranscoderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws IOException {
    String host = data.consumeRemainingAsString();

    byte[] svg =
        ("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\""
                + " >\n"
                + "<image width=\"50\" height=\"50\" xlink:href=\"https://"
                + host
                + "/\"></image>\n"
                + "</svg>")
            .getBytes();

    // Convert SVG to JPEG
    try {
      JPEGTranscoder transcoder = new JPEGTranscoder();
      TranscoderInput input = new TranscoderInput(new ByteArrayInputStream(svg));
      TranscoderOutput output = new TranscoderOutput(new ByteArrayOutputStream());
      transcoder.transcode(input, output);
    } catch (TranscoderException | IllegalArgumentException e) {
      // Ignored
    }
  }
}
