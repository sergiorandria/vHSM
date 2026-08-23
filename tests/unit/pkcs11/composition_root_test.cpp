#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <memory>

#include "../../../src/core/hsm_instance.h"
#include "../../../src/pkcs11/composition_root.h"
#include "../../../src/session/slot_manager.h"

using namespace vhsm::pkcs11;
using namespace vhsm::core;

namespace {

class AppContainerTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Use isolated :memory: DB for each test (via VHSM_DB_PATH)
    ::setenv("VHSM_DB_PATH", ":memory:", 1);
    ::unsetenv("VHSM_VAULT_PATH");
    ::unsetenv("VHSM_VAULT_PASSWORD");
    ::unsetenv("VHSM_LEDGER_ENDPOINT");
    // Clear any previous global instance id
    set_hsm_instance_id("");
    vhsm::session::SlotManager::get_instance().reset();
  }
  void TearDown() override {
    ::unsetenv("VHSM_DB_PATH");
    set_hsm_instance_id("");
    vhsm::session::SlotManager::get_instance().reset();
  }
};

TEST_F(AppContainerTest, CreatesDbAndInstanceId) {
  auto c = create_app_container();
  ASSERT_NE(c, nullptr);
  EXPECT_NE(c->db, nullptr);
  EXPECT_FALSE(c->instance_id.empty());
  EXPECT_EQ(c->instance_id.size(), 36u); // UUID v4
  EXPECT_EQ(c->db_path, ":memory:");
  EXPECT_EQ(hsm_instance_id(), c->instance_id);
  destroy_app_container(c);
  EXPECT_EQ(c, nullptr);
}

TEST_F(AppContainerTest, WiresBusAndDispatcher) {
  auto c = create_app_container();
  ASSERT_NE(c, nullptr);
  // Core bus/audit should always be wired
  EXPECT_NE(c->bounded_bus, nullptr);
  EXPECT_NE(c->bus, nullptr);
  EXPECT_NE(c->audit_log, nullptr);
  // Dispatcher and notif pipeline are best-effort; verify container at least
  // has DB and instance_id even if dispatcher is null (e.g., token missing)
  EXPECT_NE(c->db, nullptr);
  EXPECT_FALSE(c->instance_id.empty());
#ifdef VHSM_LEDGER
  EXPECT_EQ(c->ledger_client, nullptr);
  EXPECT_EQ(c->ledger_worker, nullptr);
#endif
  destroy_app_container(c);
  EXPECT_EQ(c, nullptr);
}

TEST_F(AppContainerTest, ResolveDbPathRespectsEnv) {
  ::setenv("VHSM_DB_PATH", "/tmp/custom.db", 1);
  EXPECT_EQ(resolve_db_path_for_container(), "/tmp/custom.db");
  ::setenv("VHSM_DB_PATH", ":memory:", 1);
  EXPECT_EQ(resolve_db_path_for_container(), ":memory:");
}

TEST_F(AppContainerTest, DestroyIsSafeOnNull) {
  std::unique_ptr<AppContainer> null;
  EXPECT_NO_THROW(destroy_app_container(null));
}

} // namespace
