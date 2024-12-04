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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.cap;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.extendWithZeros;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.infiniteZeros;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.readAllBytes;
import static com.google.common.truth.Truth.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class InputStreamSupportTest {
  @Test
  void testInfiniteZeros() throws IOException {
    InputStream input = infiniteZeros();

    assertThat(input.available()).isEqualTo(Integer.MAX_VALUE);
    assertThat(input.read()).isEqualTo(0);

    input.close();

    assertThat(input.available()).isEqualTo(Integer.MAX_VALUE);
    assertThat(input.read()).isEqualTo(0);
  }

  @Test
  void testExtendWithNullInputStream_empty() throws IOException {
    InputStream input = extendWithZeros(new ByteArrayInputStream(new byte[0]));
    assertThat(input.skip(5)).isEqualTo(5);
    assertThat(input.read()).isEqualTo(0);
    byte[] bytes = new byte[] {9, 9, 9, 9, 9};
    assertThat(input.read(bytes)).isEqualTo(5);
    assertThat(bytes).asList().containsExactly((byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0);
  }

  @Test
  void testExtendWithNullInputStream_emptyAfterRead() throws IOException {
    InputStream input = extendWithZeros(new ByteArrayInputStream(new byte[] {1}));
    assertThat(input.read()).isEqualTo(1);
    assertThat(input.read()).isEqualTo(0);
    assertThat(input.read()).isEqualTo(0);
    byte[] bytes = new byte[] {9, 9, 9, 9, 9};
    assertThat(input.read(bytes)).isEqualTo(5);
    assertThat(bytes).asList().containsExactly((byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0);
  }

  @Test
  void testExtendWithNullInputStream_emptyWithinRead() throws IOException {
    InputStream input = extendWithZeros(new ByteArrayInputStream(new byte[] {1, 2, 3}));
    byte[] bytes = new byte[] {9, 9, 9, 9, 9};
    assertThat(input.read(bytes)).isEqualTo(5);
    assertThat(bytes).asList().containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 0, (byte) 0);
  }

  @Test
  void testExtendWithNullInputStream_emptyWithinSkip() throws IOException {
    InputStream input = extendWithZeros(new ByteArrayInputStream(new byte[] {1, 2, 3}));
    assertThat(input.skip(5)).isEqualTo(5);
    byte[] bytes = new byte[] {9, 9, 9, 9, 9};
    assertThat(input.read(bytes)).isEqualTo(5);
    assertThat(bytes).asList().containsExactly((byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0);
  }

  @Test
  void testCap_reachedAfterRead() throws IOException {
    InputStream input = cap(new ByteArrayInputStream(new byte[] {1, 2, 3, 4, 5}), 3);
    assertThat(input.available()).isEqualTo(3);
    assertThat(input.read()).isEqualTo(1);
    assertThat(input.available()).isEqualTo(2);
    assertThat(input.read()).isEqualTo(2);
    assertThat(input.available()).isEqualTo(1);
    assertThat(input.read()).isEqualTo(3);
    assertThat(input.available()).isEqualTo(0);
    assertThat(input.read()).isEqualTo(-1);
    assertThat(input.read(new byte[5], 0, 5)).isEqualTo(-1);
  }

  @Test
  void testCap_reachedWithinRead() throws IOException {
    InputStream input = cap(new ByteArrayInputStream(new byte[] {1, 2, 3, 4, 5}), 3);
    byte[] bytes = new byte[5];
    assertThat(input.available()).isEqualTo(3);
    assertThat(input.read(bytes, 0, 5)).isEqualTo(3);
    assertThat(bytes).asList().containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 0, (byte) 0);
  }

  @ParameterizedTest
  // 8192 is the internal buffer size.
  @ValueSource(ints = {0, 1, 3, 500, 8192, 8192 + 17, 8192 * 8192 + 17})
  void testReadAllBytes(int length) throws IOException {
    byte[] bytes = new byte[length];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) i;
    }
    InputStream input = new ByteArrayInputStream(bytes);

    assertThat(readAllBytes(input)).isEqualTo(bytes);
  }
}
