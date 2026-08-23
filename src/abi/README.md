# Base ABI — vHSM

Versioned, visibility-controlled, `[[nodiscard]]`-hardened ABI that lets the
compiler fire at peak (`-O3 -flto -fvisibility=hidden -fvisibility-inlines-hidden
-Werror -Wextra -Wpedantic`).

## Layout

```
src/abi/
  export.h      → VHSM_API / VHSM_HIDDEN / VHSM_NODISCARD, inline namespace v1
  version.h.in  → generated from CMake project(VERSION)
  result.h      → std::expected-based Result<T> with nodiscard
  span.h        → bounds-checked span view
  error.h       → typed error_category + error_code
include/vhsm/abi/
  base.h        → public umbrella (includes src/abi/*)
```

## Rules

*   Every public symbol is `VHSM_API` (default) or `VHSM_HIDDEN` (internal).
    Default visibility is `hidden` (`-fvisibility=hidden`); only `VHSM_API` is
    exported. Prevents accidental ABI leakage and enables LTO to devirtualize.
*   Every fallible function returns `[[nodiscard]] Result<T>` or `[[nodiscard]]`
    `Status`; ignoring it is `-Werror=unused-result`.
*   Inline namespace `vhsm::v1` is the ABI version. Bumping `project(VERSION)` 
    to `2.0.0` creates `vhsm::v2` without breaking `v1` consumers (dual-ABI).
*   No exceptions cross the ABI boundary — `Result<T>` carries `error_code`.

## Compiler peak

`cmake/CompilerFlags.cmake` is included by top `CMakeLists.txt`:

*   `Release` → `-O3 -flto -fvisibility=hidden -fvisibility-inlines-hidden`
*   `RelWithDebInfo` → `-O2 -g -flto`
*   `ASan` preset → `-fsanitize=address,undefined`

All warnings are `-Werror`.
