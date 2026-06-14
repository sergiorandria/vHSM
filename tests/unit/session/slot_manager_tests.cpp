/**
 * slot_manager_tests.cpp
 *
 * Unit tests for vhsm::session::SlotManager
 *
 * Build (example):
 *   g++ -std=c++17 -Wall -Wextra \
 *       slot_manager_tests.cpp \
 *       ../../../src/session/slot_manager.cpp \
 *       ../../../src/keystore/slot.cpp \
 *       ../../../src/keystore/token.cpp \
 *       -lgtest -lgtest_main -lpthread \
 *       -o slot_manager_tests
 *   ./slot_manager_tests
 */

#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <algorithm> // Pour std::find
#include <memory>

#include "../../../src/session/slot_manager.h"
#include "../../../src/keystore/slot.h"
#include "../../../src/keystore/token.h"

using namespace vhsm;
using namespace vhsm::session;

// ============================================================
// Fixture
// ============================================================
class SlotManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        SlotManager::get_instance().reset();
    }

    void TearDown() override {
        SlotManager::get_instance().reset();
    }
};

// ============================================================
// TESTS UNITAIRES POUR LE SINGLETON SLOTMANAGER
// ============================================================

TEST_F(SlotManagerTest, RegisterAndRetrieveSlot) {
    auto& manager = SlotManager::get_instance();
    
    EXPECT_TRUE(manager.register_slot(0));
    EXPECT_TRUE(manager.register_slot(1));
    
    EXPECT_FALSE(manager.register_slot(0)); // Already exists
    
    auto slot = manager.get_slot(0);
    ASSERT_NE(slot, nullptr);
    EXPECT_EQ(slot->get_id(), 0u);
    
    slot = manager.get_slot(1);
    ASSERT_NE(slot, nullptr);
    EXPECT_EQ(slot->get_id(), 1u);
    
    EXPECT_EQ(manager.get_slot(999), nullptr); // Non-existent slot
}

TEST_F(SlotManagerTest, GetSlotIdList) {
    auto& manager = SlotManager::get_instance();
    
    manager.register_slot(10);
    manager.register_slot(20);
    manager.register_slot(30);
    
    std::vector<uint64_t> ids = manager.get_slot_id_list();
    EXPECT_EQ(ids.size(), 3u);
    
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 10) != ids.end());
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 20) != ids.end());
    EXPECT_TRUE(std::find(ids.begin(), ids.end(), 30) != ids.end());
    
    // Test order doesn't matter, but we got what we inserted
    // Note: unordered_map doesn't guarantee order
}

TEST_F(SlotManagerTest, SlotManagerIsSingleton) {
    auto& manager1 = SlotManager::get_instance();
    auto& manager2 = SlotManager::get_instance();
    
    EXPECT_EQ(&manager1, &manager2); // Same instance
    
    manager1.register_slot(42);
    
    auto slot = manager2.get_slot(42);
    ASSERT_NE(slot, nullptr);
    EXPECT_EQ(slot->get_id(), 42u);
}

TEST_F(SlotManagerTest, ResetClearsAllSlots) {
    auto& manager = SlotManager::get_instance();
    
    manager.register_slot(1);
    manager.register_slot(2);
    
    EXPECT_NE(manager.get_slot(1), nullptr);
    EXPECT_NE(manager.get_slot(2), nullptr);
    
    manager.reset();
    
    EXPECT_EQ(manager.get_slot(1), nullptr);
    EXPECT_EQ(manager.get_slot(2), nullptr);
    
    // After reset, we should be able to register again
    EXPECT_TRUE(manager.register_slot(1)); // Should succeed now
}

// Test slot functionality through manager
TEST_F(SlotManagerTest, SlotTokenOperationsViaManager) {
    auto& manager = SlotManager::get_instance();
    
    manager.register_slot(5);
    auto slot = manager.get_slot(5);
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
// TEST DE CONCURRENCE (THREAD-SAFETY)
// ============================================================

TEST_F(SlotManagerTest, ConcurrentSlotAccessAndInsertion) {
    auto& manager = SlotManager::get_instance();
    manager.register_slot(0);
    auto slot = manager.get_slot(0);
    
    const int num_threads = 20;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([slot, i]() {
            auto tok = std::make_shared<keystore::Token>("Thread-token-" + std::to_string(i), "Thread-ID-" + std::to_string(i));
            slot->insert_token(tok);
            
            auto active_token = slot->get_token();
            if (active_token) {
                std::string label = active_token->get_label();
                // Just verifying we can access it without crashing
            }
            
            slot->remove_token();
        });
    }
    
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    SUCCEED(); // If we reach here without crashing, the test passes
}

TEST_F(SlotManagerTest, ConcurrentSlotRegistration) {
    auto& manager = SlotManager::get_instance();
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads, false);
    
    for (int i = 0; i < num_threads; ++i) {
        int slot_id = i * 100; // Different slot IDs to avoid conflicts
        threads.emplace_back([&manager, slot_id, &results, i]() {
            results[i] = manager.register_slot(slot_id);
        });
    }
    
    for (auto& t : threads) {
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
        auto slot = manager.get_slot(slot_id);
        ASSERT_NE(slot, nullptr) << "Slot " << slot_id << " not found after registration";
        EXPECT_EQ(slot->get_id(), static_cast<uint64_t>(slot_id));
    }
}
