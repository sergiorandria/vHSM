# Per-target hardening extras.
#
# Global hardening (warnings, stack protector, FORTIFY_SOURCE, relro/now,
# PIE) and optimization/LTO are configured centrally in the top-level
# CMakeLists.txt via add_compile_options()/CMAKE_INTERPROCEDURAL_OPTIMIZATION.
# This helper only adds flags that must stay opt-in per target.
#
# Usage: vhsm_target_hardening(my_target)
#
# NOTE: -fvisibility=hidden hides ALL symbols; only use on targets that
# export explicitly annotated symbols (e.g. PKCS#11 modules exporting
# C_GetFunctionList). Never apply it to targets relying on default exports.
function(vhsm_target_hardening TARGET)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${TARGET} PRIVATE
            -fvisibility=hidden
            -fvisibility-inlines-hidden
        )
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        # /GL (whole program opt) and linker-side equivalents are handled
        # by CMAKE_INTERPROCEDURAL_OPTIMIZATION_* in the top-level file.
    endif()
endfunction()

# Backwards-compatible alias for the previous name.
function(add_hardening_flags TARGET)
    vhsm_target_hardening(${TARGET})
endfunction()
