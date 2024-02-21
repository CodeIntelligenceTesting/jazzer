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

package com.code_intelligence.jazzer.runtime;

import org.junit.Test;

import java.util.function.BiConsumer;

import static com.code_intelligence.jazzer.runtime.StateExplorer.EXPLORE_STATE_START_ID;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class StateExplorerTest {

  @Test
  public void dontTrackUnknownCoverageIds() {
    int[][] relatedCoverageIds = new int[][] {
        {1, 2, 3, 4, 5, 6},
    };
    @SuppressWarnings("unchecked")
    BiConsumer<Byte, Integer> exploreStateFunction = mock(BiConsumer.class);
    StateExplorer explorer = new StateExplorer(relatedCoverageIds, exploreStateFunction);

    explorer.recordCoverage(0);

    verify(exploreStateFunction, never()).accept(anyByte(), anyInt());
  }

  @Test
  public void exploreStateForEveryGroup() {
    int[][] relatedCoverageIds = new int[][] {
        {1, 0, 0, 0, 0, 0},
        {0, 1, 0, 0, 0, 0},
        {0, 0, 1, 0, 0, 0},
        {0, 0, 0, 0, 0, 0}
    };
    @SuppressWarnings("unchecked")
    BiConsumer<Byte, Integer> exploreStateFunction = mock(BiConsumer.class);
    StateExplorer explorer = new StateExplorer(relatedCoverageIds, exploreStateFunction);

    explorer.recordCoverage(1);

    verify(exploreStateFunction).accept( (byte) 1, EXPLORE_STATE_START_ID);
    verify(exploreStateFunction).accept( (byte) 2, EXPLORE_STATE_START_ID + 1);
    verify(exploreStateFunction).accept( (byte) 4, EXPLORE_STATE_START_ID + 2);
  }

  @Test
  public void recordMultipleCoverageIds() {
    int[][] relatedCoverageIds = new int[][] {
        {1, 2, 0, 0, 0, 0},
        {0, 1, 2, 0, 0, 0},
        {0, 0, 1, 2, 0, 0},
        {0, 0, 0, 0, 0, 0}
    };
    @SuppressWarnings("unchecked")
    BiConsumer<Byte, Integer> exploreStateFunction = mock(BiConsumer.class);
    StateExplorer explorer = new StateExplorer(relatedCoverageIds, exploreStateFunction);

    explorer.recordCoverage(1);
    explorer.recordCoverage(2);

    verify(exploreStateFunction).accept( (byte) 3, EXPLORE_STATE_START_ID);
    verify(exploreStateFunction).accept( (byte) 6, EXPLORE_STATE_START_ID + 1);
    verify(exploreStateFunction).accept( (byte) 12, EXPLORE_STATE_START_ID + 2);
  }

  @Test
  public void clearCoverageResetsTracking() {
    int[][] relatedCoverageIds = new int[][] {
            {1, 2, 0, 0, 0, 0},
    };
    @SuppressWarnings("unchecked")
    BiConsumer<Byte, Integer> exploreStateFunction = mock(BiConsumer.class);
    StateExplorer explorer = new StateExplorer(relatedCoverageIds, exploreStateFunction);

    explorer.recordCoverage(1);
    verify(exploreStateFunction).accept((byte) 1, EXPLORE_STATE_START_ID);

    explorer.clearCoverage();

    explorer.recordCoverage(2);
    verify(exploreStateFunction).accept((byte) 2, EXPLORE_STATE_START_ID);
  }
}
