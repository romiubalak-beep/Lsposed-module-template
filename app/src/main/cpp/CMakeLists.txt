cmake_minimum_required(VERSION 3.18.1)
project("native_hook")

# تضمين Dobby كوحدة فرعية
if(NOT TARGET dobby)
    set(DOBBY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Dobby)
    macro(SET_OPTION option value)
        set(${option} ${value} CACHE INTERNAL "" FORCE)
    endmacro()
    SET_OPTION(DOBBY_DEBUG OFF)
    SET_OPTION(DOBBY_GENERATE_SHARED OFF)  # إنشاء مكتبة ثابتة، وليس so
    add_subdirectory(${DOBBY_DIR} dobby)
endif()

add_library(native_hook SHARED native_hook.cpp)

target_include_directories(native_hook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DOBBY_DIR}/include
    ${DOBBY_DIR}/builtin-plugin
    ${DOBBY_DIR}/builtin-plugin/SymbolResolver
    ${DOBBY_DIR}/external/logging
)

target_link_libraries(native_hook dobby log android dl)
