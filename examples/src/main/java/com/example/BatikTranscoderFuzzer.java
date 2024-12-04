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
