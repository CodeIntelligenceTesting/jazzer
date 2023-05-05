#include "slicer/writer.h"
#include <iostream>

class JazzerJvmtiAllocator : public dex::Writer::Allocator {
  public:
    JazzerJvmtiAllocator(jvmtiEnv* jvmti_env) : jvmti_env_(jvmti_env){}

    virtual void * Allocate(size_t size){
        unsigned char* alloc = nullptr;
        jvmtiError error_num = jvmti_env_->Allocate(size, &alloc);

        if(error_num != JVMTI_ERROR_NONE) {
            std::cout << "JazzerJvmtiAllocator Allocation error. JVMTI error: " << error_num << std::endl;
        }

        return (void*)alloc;
    }

    virtual void Free(void* ptr){
        if(ptr == nullptr){
            return;
        }

        jvmtiError error_num = jvmti_env_->Deallocate((unsigned char*)ptr);

        if(error_num != JVMTI_ERROR_NONE){
            std::cout << "JazzerJvmtiAllocator Free error. JVMTI error: " << error_num << std::endl;
        }
    }

  private:
    jvmtiEnv* jvmti_env_;
};