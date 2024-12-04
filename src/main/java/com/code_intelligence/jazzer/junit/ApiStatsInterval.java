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

package com.code_intelligence.jazzer.junit;

import static java.util.Comparator.comparing;
import static java.util.Map.Entry.comparingByKey;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.utils.Log;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApiStatsInterval implements ApiStats {
  public static final String NO_STATS = "";

  private static final long timeIntervalForStatsPrint = 5000;
  private final Map<String, Stat> stats;
  private long currentTime;

  public ApiStatsInterval() {
    this.stats = new HashMap<>();
    this.currentTime = System.currentTimeMillis();
  }

  // currently not thread-safe.
  @Override
  public void addStat(String endpointUri, String method, int responseStatusCode) {
    String key = endpointUri + method;

    Stat stat = stats.computeIfAbsent(key, k -> new Stat(endpointUri, method));
    stat.addResponseStatusCount(String.valueOf(responseStatusCode));

    // Write to stderr for cifuzz to pick up
    if (System.currentTimeMillis() - currentTime > timeIntervalForStatsPrint) {
      currentTime = System.currentTimeMillis();
      Log.println(stringify());
    }
  }

  // print the info in the following format (e.g.):
  // ==API STATS==
  // {"endpoints":[{"method":"PUT","URL":"/v3/user/{id}/details","statusCodes":{"200":32,"403":104,"500":43}}]}
  @Override
  public String stringify() {
    if (stats.isEmpty()) {
      return NO_STATS;
    }
    StringBuilder sb = new StringBuilder("==API STATS== {\"endpoints\":[");
    // sort the stats by method and then by URL so that the output is deterministic
    List<Stat> sortedValues =
        stats.values().stream()
            .sorted(comparing((Stat s) -> s.method).thenComparing(s -> s.endpointUri))
            .collect(toList());
    for (Stat stat : sortedValues) {
      sb.append("{\"method\":\"");
      sb.append(stat.method);
      sb.append("\",\"URL\":\"");
      sb.append(stat.endpointUri);
      sb.append("\",\"statusCodes\":{");
      Map<String, Integer> counts = stat.responseStatusCounts;
      // sort the entries by status code, so that the output is deterministic
      List<Map.Entry<String, Integer>> sortedEntries =
          counts.entrySet().stream().sorted(comparingByKey()).collect(toList());

      for (Map.Entry<String, Integer> status : sortedEntries) {
        sb.append("\"");
        sb.append(status.getKey());
        sb.append("\":");
        sb.append(status.getValue());
        sb.append(",");
      }
      sb.deleteCharAt(sb.length() - 1);
      sb.append("}}");
      sb.append(",");
    }
    if (!sortedValues.isEmpty()) {
      sb.deleteCharAt(sb.length() - 1);
    }
    sb.append("]}");
    return sb.toString();
  }

  static final class Stat {
    final String endpointUri;
    final String method;
    final Map<String, Integer> responseStatusCounts;

    Stat(String endpointUri, String method) {
      this.endpointUri = endpointUri;
      this.method = method;
      this.responseStatusCounts = new HashMap<>();
    }

    void addResponseStatusCount(String responseStatus) {
      responseStatusCounts.compute(responseStatus, (k, v) -> v == null ? 1 : v + 1);
    }
  }
}
