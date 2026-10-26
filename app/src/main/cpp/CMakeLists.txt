cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

add_library(native_hook SHARED native_hook.cpp)

target_compile_options(native_hook PRIVATE -fvisibility=default)

target_link_libraries(native_hook log android dl)
