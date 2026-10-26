cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES IMPORTED_LOCATION
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/libdobby.a)

add_library(native_hook SHARED native_hook.cpp)

target_include_directories(native_hook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs)

target_compile_options(native_hook PRIVATE -fvisibility=default)

target_link_libraries(native_hook dobby log android dl)
