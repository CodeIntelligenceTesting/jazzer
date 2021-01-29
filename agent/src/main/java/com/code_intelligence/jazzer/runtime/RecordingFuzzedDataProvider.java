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

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Base64;

// Wraps the native FuzzedDataProviderImpl and serializes all its return values
// into a Base64-encoded string.
final class RecordingFuzzedDataProvider implements InvocationHandler {
  private final FuzzedDataProvider target = new FuzzedDataProviderImpl();
  private final ArrayList<Object> recordedReplies = new ArrayList<>();

  private RecordingFuzzedDataProvider() {}

  // Called from native code.
  public static FuzzedDataProvider makeFuzzedDataProviderProxy() {
    return (FuzzedDataProvider) Proxy.newProxyInstance(
        RecordingFuzzedDataProvider.class.getClassLoader(), new Class[] {FuzzedDataProvider.class},
        new RecordingFuzzedDataProvider());
  }

  // Called from native code.
  public static String serializeFuzzedDataProviderProxy(FuzzedDataProvider proxy)
      throws IOException {
    return ((RecordingFuzzedDataProvider) Proxy.getInvocationHandler(proxy)).serialize();
  }

  private Object recordAndReturn(Object object) {
    recordedReplies.add(object);
    return object;
  }

  @Override
  public Object invoke(Object object, Method method, Object[] args) throws Throwable {
    if (method.isDefault()) {
      // Default methods in FuzzedDataProvider are implemented in Java and
      // don't need to be recorded.
      return method.invoke(target, args);
    } else {
      return recordAndReturn(method.invoke(target, args));
    }
  }

  private String serialize() throws IOException {
    byte[] rawOut;
    try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream()) {
      try (ObjectOutputStream objectStream = new ObjectOutputStream(byteStream)) {
        objectStream.writeObject(recordedReplies);
      }
      rawOut = byteStream.toByteArray();
    }
    return Base64.getEncoder().encodeToString(rawOut);
  }
}
