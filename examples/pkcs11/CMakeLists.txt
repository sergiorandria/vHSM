# PKCS#11 usage examples — each is a standalone executable linked
# against the vHSM PKCS#11 shared module (vhsm_pkcs11).
#
# Enable with: cmake -S . -B build -DVHSM_BUILD_EXAMPLES=ON

set(_ex
    ex01_init_and_login
    ex02_generate_keys
    ex03_sign_verify
    ex04_encrypt_decrypt
    ex05_digest_and_find
    ex06_wrap_unwrap
)

foreach(name IN LISTS _ex)
  add_executable(${name} ${name}.cpp)
  target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(${name} PRIVATE vhsm_pkcs11 vhsm_signature_store SQLite3::SQLite3)
  set_target_properties(${name} PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples/pkcs11)
endforeach()
