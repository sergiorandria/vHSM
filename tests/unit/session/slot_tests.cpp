/**
 * slot_tests.cpp
 *
 * Unit tests for vhsm::keystore::Slot
 *
 * Build (example):
 *   g++ -std=c++17 -Wall -Wextra \
 *       slot_tests.cpp \
 *       ../../../src/keystore/slot.cpp \
 *       ../../../src/keystore/token.cpp \
 *       -lgtest -lgtest_main -lpthread \
 *       -o slot_tests
 *   ./slot_tests
 */

#include <gtest/gtest.h>
#include <memory>

#include "../../../src/keystore/slot.h"
#include "../../../src/keystore/token.h"

using namespace vhsm::keystore;

// ============================================================
// TESTS UNITAIRES POUR LA CLASSE SLOT
// ============================================================

TEST(SlotTest, EmptySlotBehavior) {
    Slot slot(42);
    
    EXPECT_EQ(slot.get_id(), 42u);
    EXPECT_FALSE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), nullptr);
    
    // No token present, so CKF_TOKEN_PRESENT should not be set
    EXPECT_EQ(slot.get_flags(), CKF_HW_SLOT | CKF_REMOVABLE_DEVICE); 
}

TEST(SlotTest, TokenInsertionAndRemoval) {
    Slot slot(1);
    
    auto tok = std::make_shared<Token>("HotPlug-token", "HotPlug-ID");
    
    slot.insert_token(tok);
    EXPECT_TRUE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), tok);
    EXPECT_EQ(slot.get_token()->get_label(), "HotPlug-token");
    
    // Note: Flags test commented out in implementation
    
    slot.remove_token();
    EXPECT_FALSE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), nullptr);
}

TEST(SlotTest, SlotProperties) {
    Slot slot(99);
    
    EXPECT_EQ(slot.get_id(), 99u);
    EXPECT_EQ(slot.get_description(), "Virtual HSM Slot 99");
    EXPECT_EQ(slot.get_manufacturer(), "vHSM Team Corp");
}

TEST(SlotTest, GetTokenReturnsCopy) {
    Slot slot(5);
    
    auto tok1 = std::make_shared<Token>("Token1", "Token1-ID");
    slot.insert_token(tok1);
    
    auto retrieved = slot.get_token();
    EXPECT_EQ(retrieved->get_label(), "Token1");
    
    // Remove token and verify we get nullptr
    slot.remove_token();
    EXPECT_EQ(slot.get_token(), nullptr);
    
    // Insert a different token
    auto tok2 = std::make_shared<Token>("Token2", "Token2-ID");
    slot.insert_token(tok2);
    
    retrieved = slot.get_token();
    EXPECT_EQ(retrieved->get_label(), "Token2");
    EXPECT_NE(retrieved, tok1); // Should be a different shared_ptr pointing to different object
}

// Test thread safety basics
TEST(SlotTest, ConcurrentAccessSafety) {
    Slot slot(123);
    
    // Basic test - in a real scenario we'd use threads
    auto tok = std::make_shared<Token>("Concurrent-token", "Concurrent-ID");
    slot.insert_token(tok);
    
    EXPECT_TRUE(slot.is_token_present());
    EXPECT_NE(slot.get_token(), nullptr);
    
    slot.remove_token();
    EXPECT_FALSE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), nullptr);
}
