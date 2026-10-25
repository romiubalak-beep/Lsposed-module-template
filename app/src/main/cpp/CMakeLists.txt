cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

# إضافة مكتبة Dobby (تأكد من وجود مجلد include و libdobby.a)
# يمكنك تنزيل Dobby من GitHub ووضع الملفات في مجلد cpp/
add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/libdobby.a)

add_library(native_hook SHARED native_hook.cpp)
target_link_libraries(native_hook dobby log android)
