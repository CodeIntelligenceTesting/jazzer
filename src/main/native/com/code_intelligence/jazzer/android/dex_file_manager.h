#include <vector>

#include "jvmti.h"
#include "slicer/reader.h"

class DexFileManager {
  public:
    DexFileManager(){}

    void addDexFile(const unsigned char* bytes, int length);
    unsigned char* getClassBytes(const char* className, int dexFileIndex, jvmtiEnv* jvmti, size_t* newSize);
    uint32_t findDexFileForClass(const char* className);
    bool structureMatches(dex::Reader* oldReader, dex::Reader* newReader, const char* className);

  private:
    std::vector<unsigned char*> dexFiles;
    std::vector<int> dexFilesSize;
};