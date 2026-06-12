#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <algorithm> // Pour std::find
#include "../../../src/keystore/token.h"
#include "../../../src/keystore/slot.h"
#include "../../../src/session/slot_manager.h"

using namespace vhsm;

// ============================================================================
// 1. TESTS UNITAIRES POUR LA CLASSE TOKEN
// ============================================================================

TEST(TokenTest, InitializationAndGetters) {
    // Variable renommée 't' pour éviter le conflit avec le type 'token'
    token t("Test-token-01");
    
    EXPECT_EQ(t.get_label(), "Test-token-01");
    EXPECT_EQ(t.get_model(), "vHSM Cryptographic Engine v2");
    EXPECT_EQ(t.get_serial_number(), "69-420-vHSM-SN");
    
    EXPECT_EQ(t.get_login_state(), LoginState::PUBLIC);
    EXPECT_FALSE(t.is_user_logged());
    EXPECT_FALSE(t.is_so_logged());
}

TEST(TokenTest, LoginStateTransitions) {
    token t("Auth-token");

    t.set_login_state(LoginState::USER_LOGGED);
    EXPECT_EQ(t.get_login_state(), LoginState::USER_LOGGED);
    EXPECT_TRUE(t.is_user_logged());
    EXPECT_FALSE(t.is_so_logged());

    t.set_login_state(LoginState::SO_LOGGED);
    EXPECT_EQ(t.get_login_state(), LoginState::SO_LOGGED);
    EXPECT_FALSE(t.is_user_logged());
    EXPECT_TRUE(t.is_so_logged());
}

TEST(TokenTest, PKCS11FlagsVerification) {
    token t("Flags-token");
    uint64_t flags = t.get_flags();
    
    EXPECT_NE(flags & 0x00000001, 0u); // CKF_RNG
    EXPECT_NE(flags & 0x00000004, 0u); // CKF_LOGIN_REQUIRED
}

// ============================================================================
// 2. TESTS UNITAIRES POUR LA CLASSE SLOT
// ============================================================================

TEST(SlotTest, EmptySlotBehavior) {
    Slot slot(42);
    
    EXPECT_EQ(slot.get_id(), 42u);
    EXPECT_FALSE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), nullptr);
    
    EXPECT_EQ(slot.get_flags() & 0x00000001, 0u);
}

TEST(SlotTest, TokenInsertionAndRemoval) {
    Slot slot(1);
    
    // Correction ici : Utilisation de auto (ou std::shared_ptr<token>) 
    // et renommage de la variable en 'tok' pour éviter le conflit de type
    auto tok = std::make_shared<token>("HotPlug-token");
    
    slot.insert_token(tok);
    EXPECT_TRUE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), tok);
    EXPECT_EQ(slot.get_token()->get_label(), "HotPlug-token");
    
    EXPECT_NE(slot.get_flags() & 0x00000001, 0u);
    
    slot.remove_token();
    EXPECT_FALSE(slot.is_token_present());
    EXPECT_EQ(slot.get_token(), nullptr);
}

// ============================================================================
// 3. TESTS UNITAIRES POUR LE SINGLETON SLOTMANAGER
// ============================================================================

class SlotManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        SlotManager::get_instance().reset();
    }

    void TearDown() override {
        SlotManager::get_instance().reset();
    }
};

TEST_F(SlotManagerTest, RegisterAndRetrieveSlot) {
    auto& manager = SlotManager::get_instance();
    
    EXPECT_TRUE(manager.register_slot(0));
    EXPECT_TRUE(manager.register_slot(1));
    
    EXPECT_FALSE(manager.register_slot(0));
    
    auto slot = manager.get_slot(0);
    ASSERT_NE(slot, nullptr);
    EXPECT_EQ(slot->get_id(), 0u);
    
    EXPECT_EQ(manager.get_slot(999), nullptr);
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
}

// ============================================================================
// 4. TEST DE CONCURRENCE (THREAD-SAFETY)
// ============================================================================

TEST_F(SlotManagerTest, ConcurrentSlotAccessAndInsertion) {
    auto& manager = SlotManager::get_instance();
    manager.register_slot(0);
    auto slot = manager.get_slot(0);
    
    const int num_threads = 20;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([slot, i]() {
            // Renommé 'tok' à l'intérieur de la lambda pour la sécurité
            auto tok = std::make_shared<token>("Thread-token-" + std::to_string(i));
            slot->insert_token(tok);
            
            auto active_token = slot->get_token();
            if (active_token) {
                std::string label = active_token->get_label();
            }
            
            slot->remove_token();
        });
    }
    
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    SUCCEED();
}