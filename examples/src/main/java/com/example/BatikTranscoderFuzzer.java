// Copyright 2021 Code Intelligence GmbH
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
import org.apache.batik.transcoder.ErrorHandler;
import org.apache.batik.transcoder.TranscoderException;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.JPEGTranscoder;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class BatikTranscoderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws URISyntaxException {
        String poc = data.consumeAsciiString(50);

        poc = "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" >\n" +
                "    <image width=\"50\" height=\"50\" xlink:href=\"" + poc +  "\"></image>\n" +
                "</svg>";

        byte[] svg = poc.getBytes();

        JPEGTranscoder t = new JPEGTranscoder();
        t.setErrorHandler(new DummyErrorHandler());
        InputStream stream = new ByteArrayInputStream(svg);
        TranscoderInput input = new TranscoderInput(stream);

        // Convert SVG to JPEG
        OutputStream ostream = null;
        try {
            ostream = Files.newOutputStream(Paths.get("out.jpg"));
            TranscoderOutput output = new TranscoderOutput(ostream);
            t.transcode(input, output);

            ostream.flush();
            ostream.close();
        } catch (TranscoderException | IOException | RuntimeException e) {}
    }

    public static class DummyErrorHandler implements ErrorHandler {

        @Override
        public void error(TranscoderException e) throws TranscoderException {}

        @Override
        public void fatalError(TranscoderException e) throws TranscoderException {}

        @Override
        public void warning(TranscoderException e) throws TranscoderException {}
    }
}
