/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class ObjectInputStreamDeserialization {
  public static void fuzzerTestOneInput(byte[] data) {
    try {
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
      ois.readObject();
    } catch (IOException | ClassNotFoundException ignored) {
      // Ignored checked exception.
    } catch (NullPointerException | NegativeArraySizeException ignored) {
      // Ignored RuntimeExceptions thrown by readObject().
    }
  }
}
