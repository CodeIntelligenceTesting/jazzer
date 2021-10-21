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

package com.code_intelligence.jazzer.api;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;

public class AutofuzzTest {
  public interface UnimplementedInterface {}

  public interface ImplementedInterface {}
  public static class ImplementingClass implements ImplementedInterface {}

  @Test
  public void testConsume() {
    FuzzedDataProvider data = CannedFuzzedDataProvider.create(
        Arrays.asList((byte) 1 /* do not return null */, 0 /* first class on the classpath */,
            (byte) 1 /* do not return null */, 0 /* first constructor */));
    ImplementedInterface result = Jazzer.consume(data, ImplementedInterface.class);
    assertNotNull(result);
  }

  @Test
  public void testConsumeFailsWithoutException() {
    FuzzedDataProvider data = CannedFuzzedDataProvider.create(Collections.singletonList(
        (byte) 1 /* do not return null without searching for implementing classes */));
    assertNull(Jazzer.consume(data, UnimplementedInterface.class));
  }
}
