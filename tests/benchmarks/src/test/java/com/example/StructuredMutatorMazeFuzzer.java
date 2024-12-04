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

package com.example;

import com.code_intelligence.jazzer.api.Consumer3;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

// A variant of //examples:MazeFuzzer that uses the structured mutator.
public final class StructuredMutatorMazeFuzzer {
  private static final String[] MAZE_STRING =
      new String[] {
        "  ███████████████████",
        "    █ █ █   █ █     █",
        "█ █ █ █ ███ █ █ █ ███",
        "█ █ █   █       █   █",
        "█ █████ ███ ███ █ ███",
        "█       █   █ █ █   █",
        "█ ███ ███████ █ ███ █",
        "█ █     █ █     █   █",
        "███████ █ █ █████ ███",
        "█   █       █     █ █",
        "█ ███████ █ ███ ███ █",
        "█   █     █ █ █   █ █",
        "███ ███ █ ███ █ ███ █",
        "█     █ █ █   █     █",
        "█ ███████ █ █ █ █ █ █",
        "█ █         █ █ █ █ █",
        "█ █ █████████ ███ ███",
        "█   █   █   █ █ █   █",
        "█ █ █ ███ █████ ███ █",
        "█ █         █        ",
        "███████████████████ #",
      };

  private static final char[][] MAZE = parseMaze();
  private static final char[][] REACHED_FIELDS = parseMaze();

  enum Command {
    LEFT,
    RIGHT,
    UP,
    DOWN
  }

  public static void fuzzerTestOneInput(@NotNull List<@NotNull Command> commands) {
    executeCommands(
        commands,
        (x, y, won) -> {
          if (won) {
            throw new TreasureFoundException(commands);
          }
          // This is the key line that makes this fuzz target work: It instructs the fuzzer to track
          // every new combination of x and y as a new feature. Without it, the fuzzer would be
          // completely lost in the maze as guessing an escaping path by chance is close to
          // impossible.
          Jazzer.exploreState((byte) Objects.hash(x, y), 0);
          if (REACHED_FIELDS[y][x] == ' ') {
            // Fuzzer reached a new field in the maze, print its progress.
            REACHED_FIELDS[y][x] = '.';
            // The following line is commented out to reduce test log sizes.
            // System.out.println(renderMaze(REACHED_FIELDS));
          }
        });
  }

  private static class TreasureFoundException extends RuntimeException {
    TreasureFoundException(List<Command> commands) {
      super(renderPath(commands));
    }
  }

  private static void executeCommands(
      List<Command> commands, Consumer3<Byte, Byte, Boolean> callback) {
    byte x = 0;
    byte y = 0;
    callback.accept(x, y, false);

    for (Command command : commands) {
      byte nextX = x;
      byte nextY = y;
      switch (command) {
        case LEFT:
          nextX--;
          break;
        case RIGHT:
          nextX++;
          break;
        case UP:
          nextY--;
          break;
        case DOWN:
          nextY++;
          break;
        default:
          return;
      }
      char nextFieldType;
      try {
        nextFieldType = MAZE[nextY][nextX];
      } catch (IndexOutOfBoundsException e) {
        // Fuzzer tried to walk through the exterior walls of the maze.
        continue;
      }
      if (nextFieldType != ' ' && nextFieldType != '#') {
        // Fuzzer tried to walk through the interior walls of the maze.
        continue;
      }
      // Fuzzer performed a valid move.
      x = nextX;
      y = nextY;
      callback.accept(x, y, nextFieldType == '#');
    }
  }

  private static char[][] parseMaze() {
    return Arrays.stream(MAZE_STRING).map(String::toCharArray).toArray(char[][]::new);
  }

  private static String renderMaze(char[][] maze) {
    return Arrays.stream(maze).map(String::new).collect(Collectors.joining("\n", "\n", "\n"));
  }

  private static String renderPath(List<Command> commands) {
    char[][] mutableMaze = parseMaze();
    executeCommands(
        commands,
        (x, y, won) -> {
          if (!won) {
            mutableMaze[y][x] = '.';
          }
        });
    return renderMaze(mutableMaze);
  }
}
