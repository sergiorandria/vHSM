/**
 * slot_manager_tests.cpp
 *
 * Unit tests for vhsm::session::SlotManager (injectable, not singleton).
 */

#include <algorithm>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

#include "../../../src/keystore/slot.h"
#include "../../../src/keystore/token.h"
#include "../../../src/session/slot_manager.h"

using namespace vhsm;
using namespace vhsm::session;

// ============================================================
// Fixture — each test gets its own isolated SlotManager
// ============================================================
class SlotManagerTest : public ::testing::Test {
protected:
  void SetUp() override { manager_ = std::make_unique<SlotManager>(); }
  void TearDown() override { manager_.reset(); }

  std::unique_ptr<SlotManager> manager_;
};

// ============================================================
// Registration and lookup
// ============================================================

TEST_F(SlotManagerTest, RegisterAndRetrieveSlot) {
  EXPECT_TRUE(manager_->register_slot(0));
  EXPECT_TRUE(manager_->register_slot(1));
  EXPECT_FALSE(manager_->register_slot(0)); // Already exists

  auto slot = manager_->get_slot(0);
  ASSERT_NE(slot, nullptr);
  EXPECT_EQ(slot->get_id(), 0u);

  slot = manager_->get_slot(1);
  ASSERT_NE(slot, nullptr);
  EXPECT_EQ(slot->get_id(), 1u);

  EXPECT_EQ(manager_->get_slot(999), nullptr); // Non-existent slot
}

TEST_F(SlotManagerTest, GetSlotIdList) {
  manager_->register_slot(10);
  manager_->register_slot(20);
  manager_->register_slot(30);

  std::vector<uint64_t> ids = manager_->get_slot_id_list();
  EXPECT_EQ(ids.size(), 3u);

  EXPECT_TRUE(std::find(ids.begin(), ids.end(), 10) != ids.end());
  EXPECT_TRUE(std::find(ids.begin(), ids.end(), 20) != ids.end());
  EXPECT_TRUE(std::find(ids.begin(), ids.end(), 30) != ids.end());
}

TEST_F(SlotManagerTest, InstancesAreIndependent) {
  // Two SlotManager instances must not share state — this is the whole
  // point of removing the singleton.
  manager_->register_slot(42);

  SlotManager other;
  EXPECT_EQ(other.get_slot(42), nullptr)
      << "slot leaked between independent instances";
  EXPECT_TRUE(other.register_slot(42))
      << "independent instance should allow same slot id";

  // Original still has its slot
  EXPECT_NE(manager_->get_slot(42), nullptr);
}

TEST_F(SlotManagerTest, ResetClearsAllSlots) {
  manager_->register_slot(1);
  manager_->register_slot(2);

  EXPECT_NE(manager_->get_slot(1), nullptr);
  EXPECT_NE(manager_->get_slot(2), nullptr);

  manager_->reset();

  EXPECT_EQ(manager_->get_slot(1), nullptr);
  EXPECT_EQ(manager_->get_slot(2), nullptr);

  // After reset, we should be able to register again
  EXPECT_TRUE(manager_->register_slot(1));
}

// Test slot functionality through manager
TEST_F(SlotManagerTest, SlotTokenOperationsViaManager) {
  manager_->register_slot(5);
  auto slot = manager_->get_slot(5);
  ASSERT_NE(slot, nullptr);

  EXPECT_EQ(slot->get_id(), 5u);
  EXPECT_FALSE(slot->is_token_present());

  auto tok = std::make_shared<keystore::Token>("Manager-token", "Managed-ID");
  slot->insert_token(tok);

  EXPECT_TRUE(slot->is_token_present());
  EXPECT_EQ(slot->get_token(), tok);

  slot->remove_token();
  EXPECT_FALSE(slot->is_token_present());
  EXPECT_EQ(slot->get_token(), nullptr);
}

// ============================================================
// Concurrency (thread-safety)
// ============================================================

TEST_F(SlotManagerTest, ConcurrentSlotAccessAndInsertion) {
  manager_->register_slot(0);
  auto slot = manager_->get_slot(0);

  const int num_threads = 20;
  std::vector<std::thread> threads;

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([slot, i]() {
      auto tok =
          std::make_shared<keystore::Token>("Thread-token-" + std::to_string(i),
                                            "Thread-ID-" + std::to_string(i));
      slot->insert_token(tok);

      auto active_token = slot->get_token();
      if (active_token) {
        std::string label = active_token->get_label();
        // Just verifying we can access it without crashing
      }

      slot->remove_token();
    });
  }

  for (auto &t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }

  SUCCEED(); // If we reach here without crashing, the test passes
}

TEST_F(SlotManagerTest, ConcurrentSlotRegistration) {
  const int num_threads = 10;
  std::vector<std::thread> threads;
  std::vector<bool> results(num_threads, false);

  for (int i = 0; i < num_threads; ++i) {
    int slot_id = i * 100; // Different slot IDs to avoid conflicts
    threads.emplace_back([&mgr = *manager_, slot_id, &results, i]() {
      results[i] = mgr.register_slot(slot_id);
    });
  }

  for (auto &t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }

  // All registrations should succeed since we used different IDs
  for (int i = 0; i < num_threads; ++i) {
    EXPECT_TRUE(results[i]) << "Thread " << i << " failed to register slot";
  }

  // Verify all slots were registered
  for (int i = 0; i < num_threads; ++i) {
    int slot_id = i * 100;
    auto slot = manager_->get_slot(slot_id);
    ASSERT_NE(slot, nullptr)
        << "Slot " << slot_id << " not found after registration";
    EXPECT_EQ(slot->get_id(), static_cast<uint64_t>(slot_id));
  }
}
