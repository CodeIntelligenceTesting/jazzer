/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import java.io.IOException;
import java.util.HashMap;
import org.apache.commons.imaging.ImageReadException;
import org.apache.commons.imaging.common.bytesource.ByteSourceArray;
import org.apache.commons.imaging.formats.jpeg.JpegImageParser;

// Found https://issues.apache.org/jira/browse/IMAGING-275.
public class JpegImageParserFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    try {
      new JpegImageParser().getBufferedImage(new ByteSourceArray(input), new HashMap<>());
    } catch (IOException | ImageReadException ignored) {
    }
  }
}
