#include "../../../src/keystore/token.h"
#include "../../../src/keystore/slot.h"
#include "../../../src/session/slot_manager.h"
#include <algorithm>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace vhsm::keystore;
using namespace vhsm::session;

// ============================================================================
// 1. UNIT TESTS FOR THE Token CLASS
// ============================================================================

TEST(TokenTest, InitializationAndGetters) {
  Token t("Test-token-01", "id-01");

  EXPECT_EQ(t.get_label(), "Test-token-01");
  EXPECT_EQ(t.get_id(), "id-01");
}

// ============================================================================
// 2. UNIT TESTS FOR THE Slot CLASS
// ============================================================================

TEST(SlotTest, EmptySlotBehavior) {
  Slot slot(42);

  EXPECT_EQ(slot.get_id(), 42u);
  EXPECT_FALSE(slot.is_token_present());
  EXPECT_EQ(slot.get_token(), nullptr);
}

TEST(SlotTest, TokenInsertionAndRemoval) {
  Slot slot(1);

  auto tok = std::make_shared<Token>("HotPlug-token", "id-hp");

  slot.insert_token(tok);
  EXPECT_TRUE(slot.is_token_present());
  ASSERT_NE(slot.get_token(), nullptr);
  EXPECT_EQ(slot.get_token()->get_label(), "HotPlug-token");

  slot.remove_token();
  EXPECT_FALSE(slot.is_token_present());
  EXPECT_EQ(slot.get_token(), nullptr);
}

// ============================================================================
// 3. UNIT TESTS FOR SlotManager (injectable, one instance per test)
// ============================================================================

TEST(SlotManagerTest, RegisterAndRetrieveSlot) {
  SlotManager manager;

  EXPECT_TRUE(manager.register_slot(0));
  EXPECT_TRUE(manager.register_slot(1));

  EXPECT_FALSE(manager.register_slot(0));

  auto slot = manager.get_slot(0);
  ASSERT_NE(slot, nullptr);
  EXPECT_EQ(slot->get_id(), 0u);

  EXPECT_EQ(manager.get_slot(999), nullptr);
}

TEST(SlotManagerTest, GetSlotIdList) {
  SlotManager manager;

  manager.register_slot(10);
  manager.register_slot(20);
  manager.register_slot(30);

  auto ids = manager.get_slot_id_list();
  EXPECT_EQ(ids.size(), 3u);

  EXPECT_TRUE(std::find(ids.begin(), ids.end(), 10) != ids.end());
  EXPECT_TRUE(std::find(ids.begin(), ids.end(), 20) != ids.end());
  EXPECT_TRUE(std::find(ids.begin(), ids.end(), 30) != ids.end());
}

// ============================================================================
// 4. CONCURRENCY TEST (THREAD-SAFETY)
// ============================================================================

TEST(SlotManagerTest, ConcurrentSlotAccessAndInsertion) {
  SlotManager manager;
  manager.register_slot(0);
  auto slot = manager.get_slot(0);

  const int num_threads = 20;
  std::vector<std::thread> threads;

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([slot, i]() {
      auto tok = std::make_shared<Token>(
          "Thread-token-" + std::to_string(i),
          "id-" + std::to_string(i));
      slot->insert_token(tok);

      auto active_token = slot->get_token();
      if (active_token) {
        std::string label = active_token->get_label();
        (void)label;
      }

      slot->remove_token();
    });
  }

  for (auto &t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }

  SUCCEED();
}
