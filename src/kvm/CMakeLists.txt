# vHSM KVM domain port — single source of truth for enclave lifecycle.
# Depends on vhsm_kvm_vmm only via PRIVATE link in the adapter; consumers
# (composition_root, admin) depend on the IKvmEnclaveProvider port.

add_library(vhsm_kvm_port STATIC
  enclave_manager.cpp
)

target_include_directories(vhsm_kvm_port
  PUBLIC
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_kvm_port
  PUBLIC
    vhsm_log
)

# When the real VMM is available, the manager links it privately and defines VHSM_HAVE_KVM_ENCLAVE
if(TARGET vhsm_kvm)
  target_link_libraries(vhsm_kvm_port PRIVATE vhsm_kvm)
elseif(TARGET vhsm_kvm_vmm)
  target_link_libraries(vhsm_kvm_port PRIVATE vhsm_kvm_vmm)
  target_compile_definitions(vhsm_kvm_port PRIVATE VHSM_HAVE_KVM_ENCLAVE=1)
  if(EXISTS "${PROJECT_SOURCE_DIR}/kvm_module/include")
    target_include_directories(vhsm_kvm_port PRIVATE "${PROJECT_SOURCE_DIR}/kvm_module/include")
  elseif(EXISTS "${PROJECT_SOURCE_DIR}/third_party/kvm_module/include")
    target_include_directories(vhsm_kvm_port PRIVATE "${PROJECT_SOURCE_DIR}/third_party/kvm_module/include")
  endif()
endif()

target_compile_options(vhsm_kvm_port PRIVATE -Wno-deprecated-declarations)
