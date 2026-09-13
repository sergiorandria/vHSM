#ifndef VHSM_KVM_ENCLAVE_MANAGER_H
#define VHSM_KVM_ENCLAVE_MANAGER_H

#include "enclave_provider.h"

#include <memory>
#include <mutex>
#include <string>

#ifdef VHSM_HAVE_KVM_ENCLAVE
#include "vhsm_kvm/enclave.h"
#endif

namespace vhsm::kvm {

// Composition-root owned manager — single source of truth for the host enclave.
// Owns the real Enclave when Start() succeeds; GetStatus/GetMeasurement reflect
// that instance instead of a transient probe. Thread-safe.
class EnclaveManager final : public IKvmEnclaveProvider {
public:
  EnclaveManager();
  ~EnclaveManager() override;

  EnclaveStatus GetStatus() override;
  EnclaveMeasurement GetMeasurement() override;
  void Start() override;
  void Stop() override;

private:
  struct Config {
    std::string guest_elf_path;
    uint32_t mem_mb = 256;
    int cpu_pin = -1;
    bool allow_mock = false;
  };
  Config ResolveConfig() const;
  EnclaveStatus ProbeStatus(const Config& cfg) const;

  mutable std::mutex mu_;
#ifdef VHSM_HAVE_KVM_ENCLAVE
  std::unique_ptr<Enclave> enclave_;
#endif
  bool started_ = false;
  std::string last_error_;
};

} // namespace vhsm::kvm

#endif // VHSM_KVM_ENCLAVE_MANAGER_H
