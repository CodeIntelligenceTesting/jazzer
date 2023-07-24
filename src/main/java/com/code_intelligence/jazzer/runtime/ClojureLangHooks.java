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

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

@SuppressWarnings("unused")
final public class ClojureLangHooks {
    @MethodHook(type = HookType.REPLACE, targetClassName = "clojure.lang.Var", targetMethod = "getRawRoot")
    public static Object clojureWrappedContains(MethodHandle method, Object thisObject, Object[] arguments, int hookId) throws Throwable {
        Object result = (Object) method.invoke(thisObject);
        if ("clojure.string$includes_QMARK_".equals(result.getClass().getCanonicalName())
                || "clojure.string$starts_with_QMARK_".equals(result.getClass().getCanonicalName())
                || "clojure.string$ends_with_QMARK_".equals(result.getClass().getCanonicalName())
                || "clojure.string$index_of_QMARK_".equals(result.getClass().getCanonicalName())
                || "clojure.string$last_index_of_QMARK_".equals(result.getClass().getCanonicalName())) {
            return ClojureLangIFnProxy.newInstance(result, hookId);
        } else  {
            return result;
        }
    }
}