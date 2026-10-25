cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

# إضافة مكتبة Dobby (Static Library)
add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES IMPORTED_LOCATION 
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/libdobby.a)

# إضافة مكتبة الربط
add_library(native_hook SHARED native_hook.cpp)
target_link_libraries(native_hook dobby log android dl)
