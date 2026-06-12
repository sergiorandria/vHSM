/**
 * test_session_manager.cpp
 *
 * Unit tests for vhsm::session::SessionManager
 *
 * Build (example):
 *   g++ -std=c++17 -Wall -Wextra \
 *       test_session_manager.cpp session_manager.cpp session.cpp \
 *       -lgtest -lgtest_main -lpthread \
 *       -o test_session_manager
 *   ./test_session_manager
 */

#include <gtest/gtest.h>
#include "../../../src/session/session_manager.h"

using namespace vhsm::session;

// ============================================================
// Constants
// ============================================================
namespace {

constexpr CK_SLOT_ID kSlot0 = 0;
constexpr CK_SLOT_ID kSlot1 = 1;

// Valid PKCS#11 flags: CKF_SERIAL_SESSION is mandatory; add CKF_RW_SESSION for r/w.
constexpr CK_FLAGS kFlagsRW = CKF_RW_SESSION | CKF_SERIAL_SESSION;
constexpr CK_FLAGS kFlagsRO = CKF_SERIAL_SESSION;

} // anonymous namespace

// ============================================================
// Fixture
// ============================================================
class SessionManagerTest : public ::testing::Test {
protected:
    SessionManager mgr;

    // Helper: open one RW session and assert it succeeds.
    CK_SESSION_HANDLE openRW(CK_SLOT_ID slot = kSlot0) {
        CK_SESSION_HANDLE h = 0;
        EXPECT_EQ(mgr.openSession(slot, kFlagsRW, nullptr, nullptr, &h), CKR_OK);
        EXPECT_NE(h, 0UL);
        return h;
    }

    // Helper: open one RO session and assert it succeeds.
    CK_SESSION_HANDLE openRO(CK_SLOT_ID slot = kSlot0) {
        CK_SESSION_HANDLE h = 0;
        EXPECT_EQ(mgr.openSession(slot, kFlagsRO, nullptr, nullptr, &h), CKR_OK);
        EXPECT_NE(h, 0UL);
        return h;
    }
};

// ============================================================
// openSession()
// ============================================================

TEST_F(SessionManagerTest, OpenSessionReturnsOKAndNonZeroHandle) {
    CK_SESSION_HANDLE h = 0;
    CK_RV rv = mgr.openSession(kSlot0, kFlagsRW, nullptr, nullptr, &h);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_NE(h, 0UL);
}

TEST_F(SessionManagerTest, OpenSessionNullHandlePtrReturnsBadArgs) {
    EXPECT_EQ(mgr.openSession(kSlot0, kFlagsRW, nullptr, nullptr, nullptr),
              CKR_ARGUMENTS_BAD);
}

TEST_F(SessionManagerTest, OpenSessionInvalidFlagsReturnsBadArgs) {
    CK_SESSION_HANDLE h = 0;
    // Pass an unrecognised flag bit.
    CK_FLAGS badFlags = kFlagsRW | 0x8000;
    EXPECT_EQ(mgr.openSession(kSlot0, badFlags, nullptr, nullptr, &h),
              CKR_ARGUMENTS_BAD);
}

TEST_F(SessionManagerTest, OpenSessionHandlesAreUnique) {
    CK_SESSION_HANDLE h1 = openRW();
    CK_SESSION_HANDLE h2 = openRW();
    EXPECT_NE(h1, h2);
}

TEST_F(SessionManagerTest, OpenMultipleSessionsOnSameSlot) {
    CK_SESSION_HANDLE h1 = openRW();
    CK_SESSION_HANDLE h2 = openRW();
    CK_SESSION_HANDLE h3 = openRO();
    EXPECT_NE(h1, h2);
    EXPECT_NE(h2, h3);
}

TEST_F(SessionManagerTest, OpenSessionOnDifferentSlots) {
    CK_SESSION_HANDLE h0 = openRW(kSlot0);
    CK_SESSION_HANDLE h1 = openRW(kSlot1);
    EXPECT_NE(h0, h1);
}

// ============================================================
// closeSession()
// ============================================================

TEST_F(SessionManagerTest, CloseSessionReturnsOKForValidHandle) {
    CK_SESSION_HANDLE h = openRW();
    EXPECT_EQ(mgr.closeSession(h), CKR_OK);
}

TEST_F(SessionManagerTest, CloseSessionInvalidHandleReturnsHandleInvalid) {
    EXPECT_EQ(mgr.closeSession(9999), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(SessionManagerTest, CloseSessionMakesHandleInvalid) {
    CK_SESSION_HANDLE h = openRW();
    mgr.closeSession(h);
    // After close, the handle must no longer be findable.
    EXPECT_EQ(mgr.closeSession(h), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(SessionManagerTest, CloseOneOfManySessions) {
    CK_SESSION_HANDLE h1 = openRW();
    CK_SESSION_HANDLE h2 = openRW();
    EXPECT_EQ(mgr.closeSession(h1), CKR_OK);
    // h2 must still be valid.
    CK_SESSION_INFO info{};
    EXPECT_EQ(mgr.getSessionInfo(h2, &info), CKR_OK);
}

// ============================================================
// closeAllSessions()
// ============================================================

TEST_F(SessionManagerTest, CloseAllSessionsRemovesAllForSlot) {
    CK_SESSION_HANDLE h1 = openRW(kSlot0);
    CK_SESSION_HANDLE h2 = openRW(kSlot0);
    EXPECT_EQ(mgr.closeAllSessions(kSlot0), CKR_OK);

    EXPECT_EQ(mgr.closeSession(h1), CKR_SESSION_HANDLE_INVALID);
    EXPECT_EQ(mgr.closeSession(h2), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(SessionManagerTest, CloseAllSessionsOnlyAffectsTargetSlot) {
    CK_SESSION_HANDLE h0 = openRW(kSlot0);
    CK_SESSION_HANDLE h1 = openRW(kSlot1);

    mgr.closeAllSessions(kSlot0);

    // Slot0 session gone.
    EXPECT_EQ(mgr.closeSession(h0), CKR_SESSION_HANDLE_INVALID);
    // Slot1 session still alive.
    CK_SESSION_INFO info{};
    EXPECT_EQ(mgr.getSessionInfo(h1, &info), CKR_OK);
}

TEST_F(SessionManagerTest, CloseAllSessionsOnEmptySlotReturnsOK) {
    // No sessions open for slot — spec allows CKR_OK.
    EXPECT_EQ(mgr.closeAllSessions(kSlot0), CKR_OK);
}

// ============================================================
// getSessionInfo()
// ============================================================

TEST_F(SessionManagerTest, GetSessionInfoNullPtrReturnsBadArgs) {
    CK_SESSION_HANDLE h = openRW();
    EXPECT_EQ(mgr.getSessionInfo(h, nullptr), CKR_ARGUMENTS_BAD);
}

TEST_F(SessionManagerTest, GetSessionInfoInvalidHandleReturnsHandleInvalid) {
    CK_SESSION_INFO info{};
    EXPECT_EQ(mgr.getSessionInfo(9999, &info), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(SessionManagerTest, GetSessionInfoPopulatesSlotAndFlags) {
    CK_SESSION_HANDLE h = openRW(kSlot1);
    CK_SESSION_INFO info{};
    EXPECT_EQ(mgr.getSessionInfo(h, &info), CKR_OK);
    EXPECT_EQ(info.slotID, kSlot1);
    EXPECT_EQ(info.flags,  kFlagsRW);
}

TEST_F(SessionManagerTest, GetSessionInfoInitialStateIsRWPublic) {
    CK_SESSION_HANDLE h = openRW();
    CK_SESSION_INFO info{};
    mgr.getSessionInfo(h, &info);
    EXPECT_EQ(info.state, CKS_RW_PUBLIC_SESSION);
}

TEST_F(SessionManagerTest, GetSessionInfoAfterCloseReturnsHandleInvalid) {
    CK_SESSION_HANDLE h = openRW();
    mgr.closeSession(h);
    CK_SESSION_INFO info{};
    EXPECT_EQ(mgr.getSessionInfo(h, &info), CKR_SESSION_HANDLE_INVALID);
}

// ============================================================
// getSession()
// ============================================================

TEST_F(SessionManagerTest, GetSessionReturnsNonNullForValidHandle) {
    CK_SESSION_HANDLE h = openRW();
    Session* s = mgr.getSession(h);
    EXPECT_NE(s, nullptr);
}

TEST_F(SessionManagerTest, GetSessionReturnsNullForInvalidHandle) {
    EXPECT_EQ(mgr.getSession(9999), nullptr);
}

TEST_F(SessionManagerTest, GetSessionReturnsNullAfterClose) {
    CK_SESSION_HANDLE h = openRW();
    mgr.closeSession(h);
    EXPECT_EQ(mgr.getSession(h), nullptr);
}

TEST_F(SessionManagerTest, GetSessionHandleMatchesRequest) {
    CK_SESSION_HANDLE h = openRW();
    Session* s = mgr.getSession(h);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->getHandle(), h);
}

// ============================================================
// haveSession()
// ============================================================

TEST_F(SessionManagerTest, HaveSessionFalseWhenNoSessions) {
    EXPECT_FALSE(mgr.haveSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveSessionTrueAfterOpen) {
    openRW(kSlot0);
    EXPECT_TRUE(mgr.haveSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveSessionFalseAfterCloseAll) {
    openRW(kSlot0);
    mgr.closeAllSessions(kSlot0);
    EXPECT_FALSE(mgr.haveSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveSessionFalseForOtherSlot) {
    openRW(kSlot0);
    EXPECT_FALSE(mgr.haveSession(kSlot1));
}

// ============================================================
// haveROSession()
// ============================================================

TEST_F(SessionManagerTest, HaveROSessionFalseWhenNoSessions) {
    EXPECT_FALSE(mgr.haveROSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveROSessionTrueForROSession) {
    openRO(kSlot0);
    EXPECT_TRUE(mgr.haveROSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveROSessionFalseForRWOnlySession) {
    openRW(kSlot0);
    // An RW public session is NOT a RO session.
    EXPECT_FALSE(mgr.haveROSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveROSessionTrueWhenMixedSessionsExist) {
    openRW(kSlot0);
    openRO(kSlot0);
    EXPECT_TRUE(mgr.haveROSession(kSlot0));
}

TEST_F(SessionManagerTest, HaveROSessionFalseAfterClosingROSession) {
    CK_SESSION_HANDLE hRO = openRO(kSlot0);
    openRW(kSlot0);  // keep an RW session alive
    mgr.closeSession(hRO);
    EXPECT_FALSE(mgr.haveROSession(kSlot0));
}

// ============================================================
// Thread-safety smoke tests
// ============================================================

TEST_F(SessionManagerTest, ConcurrentOpenCloseDoesNotCrash) {
    // Stress-test open/close concurrently. Under TSan this will surface
    // data races; without TSan it at least validates no crashes occur.
    constexpr int kIter = 100;
    std::atomic<bool> go{false};

    auto worker = [&]() {
        while (!go.load()) { /* spin */ }
        for (int i = 0; i < kIter; ++i) {
            CK_SESSION_HANDLE h = 0;
            if (mgr.openSession(kSlot0, kFlagsRW, nullptr, nullptr, &h) == CKR_OK) {
                mgr.closeSession(h);
            }
        }
    };

    std::thread t1(worker);
    std::thread t2(worker);
    std::thread t3(worker);
    go = true;
    t1.join();
    t2.join();
    t3.join();
}

TEST_F(SessionManagerTest, ConcurrentHaveSessionDoesNotDeadlock) {
    openRW(kSlot0);
    std::atomic<bool> stop{false};

    auto reader = [&]() {
        while (!stop.load()) {
            mgr.haveSession(kSlot0);
            mgr.haveROSession(kSlot0);
        }
    };

    auto writer = [&]() {
        for (int i = 0; i < 50; ++i) {
            CK_SESSION_HANDLE h = 0;
            mgr.openSession(kSlot0, kFlagsRW, nullptr, nullptr, &h);
            mgr.closeSession(h);
        }
    };

    std::thread r(reader);
    std::thread w(writer);
    w.join();
    stop = true;
    r.join();
}