#include "enclave_manager.h"

#include "../log/logger.h"

#include <cstdlib>
#include <filesystem>

#ifdef VHSM_HAVE_KVM_ENCLAVE
#include "vhsm_kvm/kvm_device.h"
#include "vhsm_kvm/hypercall.h"
#endif

namespace vhsm::kvm {

EnclaveManager::EnclaveManager() = default;
EnclaveManager::~EnclaveManager() {
  try { Stop(); } catch (...) {}
}

EnclaveManager::Config EnclaveManager::ResolveConfig() const {
  Config c;
  if (const char* env = std::getenv("VHSM_KVM_GUEST")) {
    if (env[0] != '\0') c.guest_elf_path = env;
  }
  if (c.guest_elf_path.empty()) {
    // Portable probe: relative to current working dir and to the binary's directory.
    // No absolute host paths (e.g. /home/sergio/...) — breaks CI/portability.
    for (auto p : {"kvm_module/guest/payload.elf",
                   "third_party/kvm_module/guest/payload.elf",
                   "../kvm_module/guest/payload.elf",
                   "../third_party/kvm_module/guest/payload.elf"}) {
      if (std::filesystem::exists(p)) { c.guest_elf_path = p; break; }
    }
    if (c.guest_elf_path.empty()) c.guest_elf_path = "kvm_module/guest/payload.elf";
  }
  if (const char* v = std::getenv("VHSM_KVM_CPU_PIN")) {
    try { c.cpu_pin = std::stoi(v); } catch (...) {}
  }
  if (const char* v = std::getenv("VHSM_KVM_MEM_MB")) {
    try { c.mem_mb = static_cast<uint32_t>(std::stoul(v)); } catch (...) {}
  }
  if (const char* v = std::getenv("VHSM_KVM_ALLOW_MOCK")) c.allow_mock = std::string(v) == "1";
#ifdef VHSM_KVM_ALLOW_MOCK
  c.allow_mock = true;
#endif
  return c;
}

static bool HostHasKvm() {
#ifdef VHSM_HAVE_KVM_ENCLAVE
  return KvmDevice::host_has_kvm();
#else
  return std::filesystem::exists("/dev/kvm");
#endif
}

EnclaveStatus EnclaveManager::ProbeStatus(const Config& cfg) const {
  EnclaveStatus s;
  s.guest_elf_path = cfg.guest_elf_path;
  s.cpu_pin = cfg.cpu_pin;
  s.mem_mb = cfg.mem_mb;
  s.has_kvm = HostHasKvm();
#ifdef VHSM_HAVE_KVM_ENCLAVE
  s.enclave_enabled = true;
#else
  s.enclave_enabled = false;
#endif
  s.is_mock = cfg.allow_mock && !s.has_kvm;
  s.is_using_kvm = s.has_kvm && !s.is_mock;

  std::lock_guard<std::mutex> lk(mu_);
#ifdef VHSM_HAVE_KVM_ENCLAVE
  if (enclave_) {
    auto vs = enclave_->state();
    if (vs == vhsm::kvm::EnclaveState::Created) s.state = ProviderEnclaveState::Created;
    else if (vs == vhsm::kvm::EnclaveState::Running) s.state = ProviderEnclaveState::Running;
    else if (vs == vhsm::kvm::EnclaveState::Stopped) s.state = ProviderEnclaveState::Stopped;
    else if (vs == vhsm::kvm::EnclaveState::Failed) s.state = ProviderEnclaveState::Failed;
    else s.state = ProviderEnclaveState::Unknown;
    s.measurement_hex = enclave_->measurement_hex();
    // Hypercall health — only meaningful when Running
    if (s.state == ProviderEnclaveState::Running) {
      uint8_t out[16] = {};
      uint32_t out_len = sizeof(out);
      uint32_t rc = enclave_->hypercall(HypercallCmd::PING, nullptr, 0, out, &out_len);
      s.hypercall_ok = (rc == 0);
      s.vsock_ok = s.hypercall_ok; // vsock fallback shares same framing; future: probe CID 3
    }
    if (!last_error_.empty()) s.error_detail = last_error_;
    else if (!s.has_kvm && !cfg.allow_mock) s.error_detail = "pure isolation requires /dev/kvm (fail-closed); set VHSM_KVM_ALLOW_MOCK=1 for CI mock";
    else if (!std::filesystem::exists(cfg.guest_elf_path)) s.error_detail = "guest payload not found: " + cfg.guest_elf_path;
    return s;
  }
#endif
  // No live enclave — probe without starting
  s.state = ProviderEnclaveState::Unknown;
  if (!std::filesystem::exists(cfg.guest_elf_path)) {
    s.error_detail = "guest payload not found: " + cfg.guest_elf_path;
  } else if (!s.has_kvm && !cfg.allow_mock) {
    s.error_detail = "pure isolation requires /dev/kvm (fail-closed); set VHSM_KVM_ALLOW_MOCK=1 for CI mock";
    s.state = ProviderEnclaveState::Created;
  } else {
    s.state = ProviderEnclaveState::Created;
    if (!last_error_.empty()) s.error_detail = last_error_;
  }
  return s;
}

EnclaveStatus EnclaveManager::GetStatus() {
  Config cfg = ResolveConfig();
  EnclaveStatus s = ProbeStatus(cfg);
  log::global_logger().info("kvm", "GetStatus has_kvm=" + std::string(s.has_kvm ? "1" : "0") +
                                   " state=" + std::to_string(static_cast<int>(s.state)) +
                                   " guest=" + cfg.guest_elf_path);
  return s;
}

EnclaveMeasurement EnclaveManager::GetMeasurement() {
  Config cfg = ResolveConfig();
  EnclaveMeasurement m;
  m.has_kvm = HostHasKvm();
  std::lock_guard<std::mutex> lk(mu_);
#ifdef VHSM_HAVE_KVM_ENCLAVE
  if (enclave_) {
    m.measurement_hex = enclave_->measurement_hex();
    if (m.measurement_hex.empty() && !std::filesystem::exists(cfg.guest_elf_path))
      m.error_detail = "guest payload not found: " + cfg.guest_elf_path;
    else if (m.measurement_hex.empty() && !m.has_kvm && !cfg.allow_mock)
      m.error_detail = "enclave not started and KVM unavailable";
    else if (!last_error_.empty() && m.measurement_hex.empty())
      m.error_detail = last_error_;
    return m;
  }
#endif
  if (!std::filesystem::exists(cfg.guest_elf_path))
    m.error_detail = "guest payload not found: " + cfg.guest_elf_path + " and enclave not started";
  else {
#ifdef VHSM_HAVE_KVM_ENCLAVE
    m.error_detail = "enclave not started — measurement available after Start()";
#else
    m.error_detail = "VHSM_HAVE_KVM_ENCLAVE not compiled — measurement requires kvm_module build";
#endif
  }
  return m;
}

void EnclaveManager::Start() {
  Config cfg = ResolveConfig();
  std::lock_guard<std::mutex> lk(mu_);
  if (started_) return;
#ifdef VHSM_HAVE_KVM_ENCLAVE
  try {
    EnclaveConfig ecfg;
    ecfg.guest_elf_path = cfg.guest_elf_path;
    ecfg.mem_mb = cfg.mem_mb;
    ecfg.cpu_pin = cfg.cpu_pin;
    ecfg.mock_if_no_kvm = cfg.allow_mock;
    enclave_ = std::make_unique<Enclave>(ecfg);
    enclave_->start();
    started_ = true;
    last_error_.clear();
  } catch (const std::exception& e) {
    last_error_ = e.what();
    enclave_.reset();
    started_ = false;
    throw;
  }
#else
  last_error_ = "VHSM_HAVE_KVM_ENCLAVE not compiled";
  throw std::runtime_error(last_error_);
#endif
}

void EnclaveManager::Stop() {
  std::lock_guard<std::mutex> lk(mu_);
#ifdef VHSM_HAVE_KVM_ENCLAVE
  if (enclave_) {
    try { enclave_->stop(); } catch (...) {}
    enclave_.reset();
  }
#endif
  started_ = false;
}

IKvmEnclaveProvider* CreateEnclaveProvider() {
  return new EnclaveManager();
}

} // namespace vhsm::kvm
