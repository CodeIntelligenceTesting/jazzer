/*
 * Copyright 2023 Code Intelligence GmbH
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public enum MutationAction {
  SHRINK,
  SHRINK_CHUNK,
  GROW,
  GROW_CHUNK,
  CHANGE,
  CHANGE_CHUNK;

  public static List<MutationAction> getPossibleActions(Collection<?> c, int minSize, int maxSize) {
    List<MutationAction> actions = new ArrayList<>();
    if (c.size() > minSize) {
      actions.add(SHRINK);
      actions.add(SHRINK_CHUNK);
    }
    if (c.size() < maxSize) {
      actions.add(GROW);
      actions.add(GROW_CHUNK);
    }
    if (!c.isEmpty()) {
      actions.add(CHANGE);
      actions.add(CHANGE_CHUNK);
    }
    return actions;
  }
}
