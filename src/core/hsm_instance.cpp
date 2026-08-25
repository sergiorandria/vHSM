#include "hsm_instance.h"

#include <mutex>
#include <string>

namespace vhsm::core {

namespace {
// Process-wide instance id — guarded for Windows/Linux thread safety.
std::string g_hsm_instance_id;
std::mutex g_hsm_instance_mutex;
} // namespace

void set_hsm_instance_id(std::string id) {
  std::lock_guard<std::mutex> lk(g_hsm_instance_mutex);
  g_hsm_instance_id = std::move(id);
}

const std::string &hsm_instance_id() { return g_hsm_instance_id; }

// ------------------ HsmInstanceId ------------------
HsmInstanceId::HsmInstanceId(std::string id) noexcept : id_(std::move(id)) {}

const std::string &HsmInstanceId::value() const noexcept { return id_; }

bool HsmInstanceId::operator==(const HsmInstanceId &other) const noexcept {
  return id_ == other.id_;
}
bool HsmInstanceId::operator!=(const HsmInstanceId &other) const noexcept {
  return !(*this == other);
}

} // namespace vhsm::core
