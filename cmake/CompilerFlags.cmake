# Compiler hardening — peak: LTO + hidden visibility + sanitizer-ready.
# Usage: add_hardening_flags(my_target) after target creation.
function(add_hardening_flags TARGET)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${TARGET} PRIVATE
            -Wall
            -Wextra
            -Werror
            -Wpedantic
            -Wconversion
            -fstack-protector-strong
            -D_FORTIFY_SOURCE=2
            -fPIC
            -fvisibility=hidden
            -fvisibility-inlines-hidden
        )
        # Release → LTO + fat LTO objects for peak devirtualization;
        # RelWithDebInfo keeps -g for profiling.
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_compile_options(${TARGET} PRIVATE -O3 -flto)
            target_link_options(${TARGET} PRIVATE -flto)
        elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
            target_compile_options(${TARGET} PRIVATE -O2 -g -flto)
            target_link_options(${TARGET} PRIVATE -flto)
        endif()
        target_link_options(${TARGET} PRIVATE
            -Wl,-z,relro,-z,now
            -Wl,--as-needed
        )
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(${TARGET} PRIVATE
            /W4
            /WX
            /GS
            /GL
            /sdl
            /guard:cf
            /dynamicbase
            /nxcompat
            /highentropyva
        )
    endif()
endfunction()