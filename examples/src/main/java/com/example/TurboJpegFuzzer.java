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
import org.libjpegturbo.turbojpeg.TJ;
import org.libjpegturbo.turbojpeg.TJDecompressor;
import org.libjpegturbo.turbojpeg.TJException;
import org.libjpegturbo.turbojpeg.TJTransform;
import org.libjpegturbo.turbojpeg.TJTransformer;

public class TurboJpegFuzzer {
  static byte[] buffer = new byte[128 * 128 * 4];

  public static void fuzzerInitialize() throws TJException {
    // Trigger an early load of the native library to show the coverage counters stats in libFuzzer.
    new TJDecompressor();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int flagsDecompress = data.consumeInt();
      int flagsTransform = data.consumeInt();
      int pixelFormat = data.consumeInt(TJ.PF_RGB, TJ.PF_CMYK);
      // Specify explicit small target width/height so that we can reuse a
      // fixed-size buffer.
      int desiredWidth = data.consumeInt(1, 128);
      int desiredHeight = data.consumeInt(1, 128);
      int transformOp = data.consumeInt(TJTransform.OP_NONE, TJTransform.OP_ROT270);
      int transformOptions = data.consumeInt();
      int transformWidth = data.consumeBoolean() ? 128 : 64;
      int transformHeight = data.consumeBoolean() ? 128 : 64;
      TJDecompressor tjd;
      if (data.consumeBoolean()) {
        TJTransformer tjt = new TJTransformer(data.consumeRemainingAsBytes());
        TJTransform tjf =
            new TJTransform(
                0, 0, transformWidth, transformHeight, transformOp, transformOptions, null);
        tjd = tjt.transform(new TJTransform[] {tjf}, flagsTransform)[0];
      } else {
        tjd = new TJDecompressor(data.consumeRemainingAsBytes());
      }
      tjd.decompress(buffer, 0, 0, desiredWidth, 0, desiredHeight, pixelFormat, flagsDecompress);
    } catch (Exception ignored) {
      // We are not looking for Java exceptions, but segfaults and ASan reports.
    }
  }
}
