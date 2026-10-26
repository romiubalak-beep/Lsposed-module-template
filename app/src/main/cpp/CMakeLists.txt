cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

find_package(shadowhook REQUIRED CONFIG)

add_library(native_hook SHARED native_hook.cpp)

target_compile_options(native_hook PRIVATE -fvisibility=default)

target_link_libraries(native_hook shadowhook::shadowhook log android dl)
