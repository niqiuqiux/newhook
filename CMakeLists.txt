cmake_minimum_required(VERSION 3.10)

# ── Android NDK cross-compilation ──
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_ANDROID_NDK D:/ndkollvm/android-ndk-r25c.Ollvm/android-ndk-r25c)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)

set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-26)
set(ANDROID_NDK ${CMAKE_ANDROID_NDK})

project(newhook C)

# ARM64 only guard
if(DEFINED ANDROID_ABI AND NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "newhook only supports arm64-v8a (got ${ANDROID_ABI})")
endif()

# ── Sources ──
set(SOURCES
    src/newhook.c
    src/nh_hook.c
    src/nh_a64.c
    src/nh_trampo.c
    src/nh_enter.c
    src/nh_island.c
    src/nh_symbol.c
    src/nh_util.c
    src/nh_safe.c
)

# ── Compile flags ──
set(COMMON_FLAGS
    -std=c11
    -Wall -Wextra -Werror
    -Wno-unused-parameter
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

set(RELEASE_FLAGS -Os)
set(DEBUG_FLAGS -O0 -g -DNH_DEBUG)
set(LINK_FLAGS
    -Wl,--gc-sections
    -Wl,-z,max-page-size=16384
)

# ── Static library (.a) ──
add_library(newhook_static STATIC ${SOURCES})
target_include_directories(newhook_static PUBLIC include PRIVATE src)
target_compile_options(newhook_static PRIVATE ${COMMON_FLAGS})
target_compile_options(newhook_static PRIVATE
    $<$<CONFIG:Release>:${RELEASE_FLAGS}>
    $<$<CONFIG:RelWithDebInfo>:${RELEASE_FLAGS}>
    $<$<CONFIG:Debug>:${DEBUG_FLAGS}>
)
set_target_properties(newhook_static PROPERTIES OUTPUT_NAME newhook)

# ── Shared library (.so) ──
add_library(newhook_shared SHARED ${SOURCES})
target_include_directories(newhook_shared PUBLIC include PRIVATE src)
target_compile_options(newhook_shared PRIVATE ${COMMON_FLAGS})
target_compile_options(newhook_shared PRIVATE
    $<$<CONFIG:Release>:${RELEASE_FLAGS}>
    $<$<CONFIG:RelWithDebInfo>:${RELEASE_FLAGS}>
    $<$<CONFIG:Debug>:${DEBUG_FLAGS}>
)
target_link_options(newhook_shared PRIVATE
    ${LINK_FLAGS}
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/newhook.map
    -Wl,--exclude-libs,ALL
)
target_link_libraries(newhook_shared PRIVATE log dl)
set_target_properties(newhook_shared PROPERTIES OUTPUT_NAME newhook)

# ── Test executable (links static library) ──
add_executable(newhook_test test/test_newhook.c)
target_link_libraries(newhook_test PRIVATE newhook_static log dl)
target_compile_options(newhook_test PRIVATE -std=c11 -Wall -O0 -g -fno-builtin -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0)
target_link_options(newhook_test PRIVATE -Wl,-z,max-page-size=16384)
# PIE is required for Android executables on 64-bit
set_target_properties(newhook_test PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    LINK_FLAGS "-pie"
)
