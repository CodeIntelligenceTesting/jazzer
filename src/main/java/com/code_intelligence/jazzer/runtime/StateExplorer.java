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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * StateExplorer tracks the recording of coverage ids and calls exploreState on every provided coverage id relation,
 * which contains the recorded one. The feedback of related coverage ids should enable libFuzzer to explore code paths
 * in a more succinct way and improve overall fuzzing performance.
 */
public class StateExplorer {

    // Instance field set by agent on initialization.
    public static StateExplorer INSTANCE = null;

    // High enough start id to avoid conflicts with other feedback ids.
    static final int EXPLORE_STATE_START_ID = 1_000_000;

    /*
     * A coverage location is a pair of row and column indices in the related coverage id matrix,
     * and used for a quick lookup.
     */
    private static class CoverageLocation {
        final int row;
        final int column;

        public CoverageLocation(int row, int column) {
            this.row = row;
            this.column = column;
        }
    }

    /*
     * Convert the provided coverage id relations to a map of coverage ids to locations in the input list.
     *
     * Later on, this structure is used to quickly find the affected locations to update the status of a recorded
     * coverage id, without scanning the whole input every time.
     *
     * Input: [[id1,id2,id3,..idn], [id3,idx,idy,..idz], ...] -> Output: {id1: [(0,0)..(m,n)], id2: [(0,1)..(m,n)], ...}
     */
    private static Map<Integer, List<CoverageLocation>> toCoverageIdLocations(int[][] relatedCoverageIds) {
        // Not very memory efficient, but ok for a first iteration.
        Map<Integer, List<CoverageLocation>> coverageIdToLocation = new HashMap<>();
        for (int row = 0; row < relatedCoverageIds.length; row++) {
            int[] coverageIds = relatedCoverageIds[row];
            for (int column = 0; column < coverageIds.length; column++) {
                int coverageId = coverageIds[column];
                List<CoverageLocation> locations = coverageIdToLocation.computeIfAbsent(coverageId, k -> new ArrayList<>(1));
                locations.add(new CoverageLocation(row, column));
            }
        }
        return coverageIdToLocation;
    }

    private final Map<Integer, List<CoverageLocation>> coverageIdLocations;
    private final BiConsumer<Byte, Integer> exploreStateFunction;
    private final int[] relatedStateValues;

    public StateExplorer(int[][] relatedCoverageIds, BiConsumer<Byte, Integer> exploreStateFunction) {
        this.coverageIdLocations = toCoverageIdLocations(relatedCoverageIds);
        this.exploreStateFunction = exploreStateFunction;
        this.relatedStateValues = new int[relatedCoverageIds.length];
    }

    public void recordCoverage(final int id) {
        if (!coverageIdLocations.containsKey(id)) {
            return;
        }
        for (CoverageLocation location : coverageIdLocations.get(id)) {
            // TODO: Think about ways to include more states in the state value, e.g. creating a hash.
            // Mark id as covered by setting the corresponding bit in the related state value.
            relatedStateValues[location.row] |= 1 << location.column;
            // Call exploreState on every affected list of related coverage ids with the then valid value.
            // Truncate to byte for now, as libFuzzer does not support a higher resolution.
            int stateFeedbackId = EXPLORE_STATE_START_ID + location.row;
            exploreStateFunction.accept((byte) relatedStateValues[location.row], stateFeedbackId);
        }
    }

    public void clearCoverage() {
        Arrays.fill(relatedStateValues, 0);
    }

}
