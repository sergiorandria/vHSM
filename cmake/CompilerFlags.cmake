# Compiler hardening flags macro
function(add_hardening_flags TARGET)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${TARGET} PRIVATE
            -Wall
            -Wextra
            -Werror
            -fstack-protector-strong
            -D_FORTIFY_SOURCE=2
            -fPIE
            -pie
            -Wl,-z,relro,-z,now
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