cmake_minimum_required(VERSION 3.23)
project(cppcode)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})
include_directories(/usr/include/)
link_directories(/usr/lib/x86_64-linux-gnu)

# 将我们代码源文件都加载进来
file(GLOB SRC_FILES
        "${PROJECT_SOURCE_DIR}/*.h"
        "${PROJECT_SOURCE_DIR}/*.cpp"
        "${PROJECT_SOURCE_DIR}/*.cc"
        "${PROJECT_SOURCE_DIR}/*.c"
        )
link_libraries(bfd)   #链接第三方库

add_executable(loader ${SRC_FILES})   #加载所有源文件



#target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_17)   #打开对应的c++支持

