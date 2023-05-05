/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vector>

#include "jvmti.h"
#include "slicer/reader.h"

// DexFileManager will contain the contents to multiple DEX files
class DexFileManager {
 public:
  DexFileManager() {}

  void addDexFile(const unsigned char* bytes, int length);
  unsigned char* getClassBytes(const char* className, int dexFileIndex,
                               jvmtiEnv* jvmti, size_t* newSize);
  uint32_t findDexFileForClass(const char* className);
  bool structureMatches(dex::Reader* oldReader, dex::Reader* newReader,
                        const char* className);

 private:
  std::vector<unsigned char*> dexFiles;
  std::vector<int> dexFilesSize;
};
