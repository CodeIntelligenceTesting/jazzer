/*
 * Copyright 2021 Code Intelligence GmbH
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

#pragma once

#include <string>

constexpr const char *kBaseReproducer =
    R"java(import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_$0 {
    static final String base64Bytes = String.join("", "$1");

    public static void main(String[] args) throws Throwable {
        ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = $2.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = $2.class.getMethod("fuzzerInitialize", String[].class);
                fuzzerInitialize.invoke(null, (Object) args);
            } catch (NoSuchMethodException ignored1) {
            } catch (IllegalAccessException | InvocationTargetException e) {
                e.printStackTrace();
                System.exit(1);
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            System.exit(1);
        }
        $3
        $2.fuzzerTestOneInput(input);
    }
}
)java";

constexpr const char *kTestOneInputWithBytes =
    "byte[] input = java.util.Base64.getDecoder().decode(base64Bytes);";

constexpr const char *kTestOneInputWithData =
    "com.code_intelligence.jazzer.api.CannedFuzzedDataProvider input = new "
    "com.code_intelligence.jazzer.api.CannedFuzzedDataProvider(base64Bytes)"
    ";";
