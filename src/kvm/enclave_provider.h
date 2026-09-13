#ifndef VHSM_KVM_ENCLAVE_PROVIDER_H
#define VHSM_KVM_ENCLAVE_PROVIDER_H

#include <cstdint>
#include <string>

namespace vhsm::kvm {

// Domain port — admin and pkcs11 depend on this abstraction, not on
// vhsm_kvm/enclave.h. The concrete adapter (KvmEnclaveAdapter / NullEnclaveProvider)
// is selected at link time via VHSM_HAVE_KVM_ENCLAVE.
enum class ProviderEnclaveState { Unknown, Created, Running, Stopped, Failed };

struct EnclaveStatus {
  ProviderEnclaveState state = ProviderEnclaveState::Unknown;
  bool has_kvm = false;
  bool is_mock = false;
  bool is_using_kvm = false;
  std::string measurement_hex;   // SHA256 of guest text+rodata, hex
  std::string guest_elf_path;    // VHSM_KVM_GUEST or default
  int cpu_pin = -1;
  uint32_t mem_mb = 256;
  std::string error_detail;
  bool enclave_enabled = false;  // VHSM_HAVE_KVM_ENCLAVE compiled
  bool hypercall_ok = false;     // PING hypercall succeeded on live enclave
  bool vsock_ok = false;         // vsock fallback reachable (mirrors hypercall_ok for now)
};

struct EnclaveMeasurement {
  std::string measurement_hex;
  bool has_kvm = false;
  std::string error_detail;
};

class IKvmEnclaveProvider {
public:
  virtual ~IKvmEnclaveProvider() = default;
  virtual EnclaveStatus GetStatus() = 0;
  virtual EnclaveMeasurement GetMeasurement() = 0;
  // Optional: lifecycle for the composition root
  virtual void Start() {}
  virtual void Stop() {}
};

// Factory — returns KvmEnclaveAdapter when VHSM_HAVE_KVM_ENCLAVE else NullEnclaveProvider.
// The caller owns the returned pointer (typically moved into AppContainer).
IKvmEnclaveProvider* CreateEnclaveProvider();

} // namespace vhsm::kvm

#endif // VHSM_KVM_ENCLAVE_PROVIDER_H
