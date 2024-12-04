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
