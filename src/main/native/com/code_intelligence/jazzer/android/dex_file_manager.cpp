#include <algorithm>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#include "dex_file_manager.h"
#include "slicer/reader.h"
#include "slicer/writer.h"
#include "slicer/dex_ir.h"
#include "jazzer_jvmti_allocator.h"
#include "jvmti.h"

std::string GetName(const char* name){
    std::stringstream ss;
    ss << "L" << name << ";";
    return ss.str();
}

bool IsValidIndex(dex::u4 index){
    return index != (unsigned) -1;
}

void DexFileManager::addDexFile(const unsigned char* bytes, int length){
    unsigned char* newArr = new unsigned char[length];
    std::copy(bytes, bytes+length, newArr);

    dexFiles.push_back(newArr);
    dexFilesSize.push_back(length);
}

unsigned char* DexFileManager::getClassBytes(const char* className, int dexFileIndex, jvmtiEnv* jvmti, size_t* newSize){

    dex::Reader dexReader(dexFiles[dexFileIndex], dexFilesSize[dexFileIndex]);
    auto descName = GetName(className);

    auto classIndex = dexReader.FindClassIndex(descName.c_str());
    if(!IsValidIndex(classIndex)){
        *newSize = *newSize;
        return nullptr;
    }

    dexReader.CreateClassIr(classIndex);
    auto oldIr = dexReader.GetIr();

    dex::Writer writer(oldIr);
    JazzerJvmtiAllocator allocator(jvmti);
    return writer.CreateImage(&allocator, newSize);
}

uint32_t DexFileManager::findDexFileForClass(const char* className){
    for (int i = 0; i < dexFiles.size(); i++){
        dex::Reader dexReader(dexFiles[i], dexFilesSize[i]);

        std::string descName = GetName(className);
        dex::u4 classIndex = dexReader.FindClassIndex(descName.c_str());

        if(IsValidIndex(classIndex)){
            return i;
        }
    }

    return -1;
}

std::vector<std::string> getMethodDescriptions(std::vector<ir::EncodedMethod*>* encMethodList){
    std::vector<std::string> methodDescs;

    for(int i = 0; i < encMethodList->size(); i++){
        std::stringstream ss;
        ss << (*encMethodList)[i]->access_flags;
        ss << (*encMethodList)[i]->decl->name->c_str();
        ss << (*encMethodList)[i]->decl->prototype->Signature().c_str();

        methodDescs.push_back(ss.str());
    }

    sort(methodDescs.begin(), methodDescs.end());
    return methodDescs;
}

std::vector<std::string> getFieldDescriptions(std::vector<ir::EncodedField*>* encFieldList){
    std::vector<std::string> fieldDescs;

    for(int i = 0; i < encFieldList->size(); i++){
        std::stringstream ss;
        ss << (*encFieldList)[i]->access_flags;
        ss << (*encFieldList)[i]->decl->type->descriptor->c_str();
        ss << (*encFieldList)[i]->decl->name->c_str();
        fieldDescs.push_back(ss.str());
    }

    sort(fieldDescs.begin(), fieldDescs.end());
    return fieldDescs;
}

bool matchFields(std::vector<ir::EncodedField*>* encodedFieldListOne, std::vector<ir::EncodedField*>* encodedFieldListTwo){
    std::vector<std::string> fDescListOne = getFieldDescriptions(encodedFieldListOne);
    std::vector<std::string> fDescListTwo = getFieldDescriptions(encodedFieldListTwo);

    if(fDescListOne.size() != fDescListTwo.size()){
        return false;
    }

    for(int i = 0; i < fDescListOne.size(); i++){
        if(strcmp(fDescListOne[i].c_str(), fDescListTwo[i].c_str()) != 0){
            return false;
        }
    }

    return true;
}

bool matchMethods(std::vector<ir::EncodedMethod*>* encodedMethodListOne, std::vector<ir::EncodedMethod*>* encodedMethodListTwo){
    std::vector<std::string> mDescListOne = getMethodDescriptions(encodedMethodListOne);
    std::vector<std::string> mDescListTwo = getMethodDescriptions(encodedMethodListTwo);

    if(mDescListOne.size() != mDescListTwo.size()){
        return false;
    }

    for(int i = 0; i < mDescListOne.size(); i++){
        if(strcmp(mDescListOne[i].c_str(), mDescListTwo[i].c_str()) != 0){
            return false;
        }
    }

    return true;
}

bool classStructureMatches(ir::Class* classOne, ir::Class* classTwo){
    bool result = true;
    result = result && matchMethods(&(classOne->direct_methods), &(classTwo->direct_methods));
    result = result && matchMethods(&(classOne->virtual_methods), &(classTwo->virtual_methods));
    result = result && matchFields(&(classOne->static_fields), &(classTwo->static_fields));
    result = result && matchFields(&(classOne->instance_fields), &(classTwo->instance_fields));
    result = result && (classOne->access_flags == classTwo->access_flags);

    return result;
}

bool DexFileManager::structureMatches(dex::Reader *oldReader, dex::Reader *newReader, const char* className){
    std::string descName = GetName(className);

    dex::u4 oldReaderIndex = oldReader->FindClassIndex(descName.c_str());
    dex::u4 newReaderIndex = newReader->FindClassIndex(descName.c_str());

    if(!IsValidIndex(oldReaderIndex) || !IsValidIndex(newReaderIndex)){
        return false;
    }

    oldReader->CreateClassIr(oldReaderIndex);
    newReader->CreateClassIr(newReaderIndex);

    std::shared_ptr<ir::DexFile> oldDexFile = oldReader->GetIr();
    std::shared_ptr<ir::DexFile> newDexFile = newReader->GetIr();

    for(int i = 0; i < oldDexFile->classes.size(); i++){
        const char* oldClassDescriptor = oldDexFile->classes[i]->type->descriptor->c_str();
        if(strcmp(oldClassDescriptor, descName.c_str()) != 0){
            continue;
        }

        bool match = false;
        for(int j = 0; j < newDexFile->classes.size(); j++){
            const char* newClassDescriptor = newDexFile->classes[j]->type->descriptor->c_str();
            if(strcmp(oldClassDescriptor, newClassDescriptor) == 0){
                match = classStructureMatches(oldDexFile->classes[i].get(), newDexFile->classes[j].get());
                break;
            }
        }

        if(!match){
            return false;
        }
    }

    return true;
}
