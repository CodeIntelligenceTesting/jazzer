/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package jaz;

/**
 * A safe to use companion of {@link jaz.Zer} that is used to produce serializable instances of it
 * with only light patching.
 */
@SuppressWarnings("unused")
public class Ter implements java.io.Serializable {
  static final long serialVersionUID = 42L;

  public static final byte REFLECTIVE_CALL_SANITIZER_ID = 0;
  public static final byte DESERIALIZATION_SANITIZER_ID = 1;
  public static final byte EXPRESSION_LANGUAGE_SANITIZER_ID = 2;

  private byte sanitizer = REFLECTIVE_CALL_SANITIZER_ID;

  public Ter() {}

  public Ter(byte sanitizer) {
    this.sanitizer = sanitizer;
  }
}
