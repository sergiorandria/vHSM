/**
 * test_session.cpp
 *
 * Unit tests for vhsm::session::Session
 *
 * Build (example):
 *   g++ -std=c++17 -Wall -Wextra \
 *       test_session.cpp session.cpp \
 *       -lgtest -lgtest_main -lpthread \
 *       -o test_session
 *   ./test_session
 */

#include <gtest/gtest.h>
#include "../../../src/session/session.h"
#include "../../../src/core/types.h"
#include "../../../src/core/secure_buffer.h"
#include <thread>

// --------------------------------------------------------------------------
// Minimal stubs so the TU compiles without the full project tree.
// Remove / replace these once you link against the real build.
// --------------------------------------------------------------------------
namespace {

vhsm::SecureBuffer makePin(const char* s) {
    return vhsm::SecureBuffer(std::strlen(s));
}

constexpr CK_SESSION_HANDLE kHandle  = 1;
constexpr CK_SLOT_ID        kSlot    = 0;

} // anonymous namespace

using namespace vhsm::session;

// ============================================================
// Fixture
// ============================================================
class SessionTest : public ::testing::Test {
protected:
    // Default: read-write session (CKF_RW_SESSION | CKF_SERIAL_SESSION)
    Session rwSession {kHandle, kSlot, CKF_RW_SESSION | CKF_SERIAL_SESSION, nullptr, nullptr};

    // Read-only session
    Session roSession {kHandle + 1, kSlot, CKF_SERIAL_SESSION, nullptr, nullptr};

    const vhsm::SecureBuffer validPin  = makePin("12345678");
    const vhsm::SecureBuffer emptyPin {};
};

// ============================================================
// Construction & Getters
// ============================================================

TEST_F(SessionTest, ConstructorSetsFieldsCorrectly) {
    EXPECT_EQ(rwSession.getHandle(),   kHandle);
    EXPECT_EQ(rwSession.getSlotID(),   kSlot);
    EXPECT_EQ(rwSession.getFlags(),    CKF_RW_SESSION | CKF_SERIAL_SESSION);
}

TEST_F(SessionTest, RWSessionInitialStateIsRWPublicSession) {
    // CKF_RW_SESSION set → must start in CKS_RW_PUBLIC_SESSION per PKCS#11 §6.7.1
    EXPECT_EQ(rwSession.getState(), CKS_RW_PUBLIC_SESSION);
}

TEST_F(SessionTest, ROSessionInitialStateIsROPublicSession) {
    // CKF_RW_SESSION not set → must start in CKS_RO_PUBLIC_SESSION per PKCS#11 §6.7.1
    EXPECT_EQ(roSession.getState(), CKS_RO_PUBLIC_SESSION);
}

TEST_F(SessionTest, InitialUserTypeIsInvalid) {
    EXPECT_EQ(rwSession.getUserType(), static_cast<CK_USER_TYPE>(CKU_INVALID));
}

// ============================================================
// login()
// ============================================================

TEST_F(SessionTest, LoginUserSucceedsFromPublicState) {
    EXPECT_EQ(rwSession.login(CKU_USER, validPin), CKR_OK);
}

TEST_F(SessionTest, LoginSOSucceedsFromPublicState) {
    EXPECT_EQ(rwSession.login(CKU_SO, validPin), CKR_OK);
}

TEST_F(SessionTest, LoginUserSetsRWUserFunctionsState) {
    rwSession.login(CKU_USER, validPin);
    EXPECT_EQ(rwSession.getState(), CKS_RW_USER_FUNCTIONS);
}

TEST_F(SessionTest, LoginSOSetsSORWFunctionsState) {
    rwSession.login(CKU_SO, validPin);
    EXPECT_EQ(rwSession.getState(), CKS_RW_SO_FUNCTIONS);
}

TEST_F(SessionTest, LoginUserOnROSessionYieldsROUserFunctions) {
    roSession.login(CKU_USER, validPin);
    // After fix: read-only session + CKU_USER login = CKS_RO_USER_FUNCTIONS
    EXPECT_EQ(roSession.getState(), CKS_RO_USER_FUNCTIONS);
}

TEST_F(SessionTest, LoginSetsUserType) {
    rwSession.login(CKU_USER, validPin);
    EXPECT_EQ(rwSession.getUserType(), CKU_USER);
}

TEST_F(SessionTest, LoginInvalidUserTypeReturnsError) {
    EXPECT_EQ(rwSession.login(static_cast<CK_USER_TYPE>(0xFF), validPin),
              CKR_USER_TYPE_INVALID);
}

TEST_F(SessionTest, LoginWhenAlreadyLoggedInReturnsUserAlreadyLoggedIn) {
    rwSession.login(CKU_USER, validPin);
    CK_RV rv = rwSession.login(CKU_USER, validPin);
    // After fix: second login should return CKR_USER_ALREADY_LOGGED_IN
    EXPECT_EQ(rv, CKR_USER_ALREADY_LOGGED_IN);
}

// ============================================================
// logout()
// ============================================================

TEST_F(SessionTest, LogoutAfterLoginReturnsOK) {
    rwSession.login(CKU_USER, validPin);
    EXPECT_EQ(rwSession.logout(), CKR_OK);
}

TEST_F(SessionTest, LogoutResetsUserType) {
    rwSession.login(CKU_USER, validPin);
    rwSession.logout();
    EXPECT_EQ(rwSession.getUserType(), static_cast<CK_USER_TYPE>(CKU_INVALID));
}

TEST_F(SessionTest, LogoutOnRWSessionRestoresRWPublicState) {
    rwSession.login(CKU_USER, validPin);
    rwSession.logout();
    EXPECT_EQ(rwSession.getState(), CKS_RW_PUBLIC_SESSION);
}

TEST_F(SessionTest, LogoutOnROSessionRestoresROPublicState) {
    roSession.login(CKU_USER, validPin);
    roSession.logout();
    EXPECT_EQ(roSession.getState(), CKS_RO_PUBLIC_SESSION);
}

TEST_F(SessionTest, LogoutWhenNotLoggedInReturnsUserNotLoggedIn) {
    EXPECT_EQ(rwSession.logout(), CKR_USER_NOT_LOGGED_IN);
}

TEST_F(SessionTest, DoubleLogoutReturnsUserNotLoggedIn) {
    rwSession.login(CKU_USER, validPin);
    rwSession.logout();
    EXPECT_EQ(rwSession.logout(), CKR_USER_NOT_LOGGED_IN);
}

// ============================================================
// initializeOperation()
// ============================================================

TEST_F(SessionTest, InitOperationRequiresLogin) {
    // Not logged in — must fail.
    EXPECT_EQ(rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0),
              CKR_USER_NOT_LOGGED_IN);
}

TEST_F(SessionTest, InitOperationSucceedsWhenLoggedIn) {
    rwSession.login(CKU_USER, validPin);
    EXPECT_EQ(rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0), CKR_OK);
}

TEST_F(SessionTest, InitOperationTwiceReturnsOperationActive) {
    rwSession.login(CKU_USER, validPin);
    rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0);
    EXPECT_EQ(rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0),
              CKR_OPERATION_ACTIVE);
}

TEST_F(SessionTest, InitOperationAfterFinalizeSucceeds) {
    rwSession.login(CKU_USER, validPin);
    rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0);
    rwSession.finalizeOperation();
    EXPECT_EQ(rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0), CKR_OK);
}

// ============================================================
// finalizeOperation()
// ============================================================

TEST_F(SessionTest, FinalizeWithNoOperationReturnsNotInitialized) {
    rwSession.login(CKU_USER, validPin);
    EXPECT_EQ(rwSession.finalizeOperation(), CKR_OPERATION_NOT_INITIALIZED);
}

TEST_F(SessionTest, FinalizeAfterInitReturnsOK) {
    rwSession.login(CKU_USER, validPin);
    rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0);
    EXPECT_EQ(rwSession.finalizeOperation(), CKR_OK);
}

TEST_F(SessionTest, DoubleFinalizeFails) {
    rwSession.login(CKU_USER, validPin);
    rwSession.initializeOperation(CKM_AES_CBC, nullptr, 0);
    rwSession.finalizeOperation();
    EXPECT_EQ(rwSession.finalizeOperation(), CKR_OPERATION_NOT_INITIALIZED);
}

// ============================================================
// getSessionInfo()
// ============================================================

TEST_F(SessionTest, GetSessionInfoPopulatesFieldsROSession) {
    CK_SESSION_INFO info{};
    roSession.getSessionInfo(&info);

    EXPECT_EQ(info.slotID,         kSlot);
    EXPECT_EQ(info.state,          CKS_RO_PUBLIC_SESSION);
    EXPECT_EQ(info.flags,          CKF_SERIAL_SESSION);
    EXPECT_EQ(info.ulDeviceError,  0UL);
}

TEST_F(SessionTest, GetSessionInfoPopulatesFieldsRWSession) {
    CK_SESSION_INFO info{};
    rwSession.getSessionInfo(&info);

    EXPECT_EQ(info.slotID,         kSlot);
    EXPECT_EQ(info.state,          CKS_RW_PUBLIC_SESSION);
    EXPECT_EQ(info.flags,          CKF_RW_SESSION | CKF_SERIAL_SESSION);
    EXPECT_EQ(info.ulDeviceError,  0UL);
}

TEST_F(SessionTest, GetSessionInfoNullPtrDoesNotCrash) {
    // Should not crash (current impl silently returns).
    EXPECT_NO_FATAL_FAILURE(rwSession.getSessionInfo(nullptr));
}

TEST_F(SessionTest, GetSessionInfoReflectsStateAfterLogin) {
    rwSession.login(CKU_USER, validPin);
    CK_SESSION_INFO info{};
    rwSession.getSessionInfo(&info);
    EXPECT_EQ(info.state, CKS_RW_USER_FUNCTIONS);
}

// ============================================================
// ObjectStore access (smoke tests)
// ============================================================

TEST_F(SessionTest, GetObjectStoreReturnsSameRef) {
    // Verify the non-const and const overloads return the same object.
    const Session& constRef = rwSession;
    EXPECT_EQ(&rwSession.getObjectStore(), &constRef.getObjectStore());
}

// ============================================================
// Thread-safety smoke test
// ============================================================

TEST_F(SessionTest, ConcurrentLoginLogoutDoesNotDeadlock) {
    // Hammer login/logout from two threads. If there's a deadlock or data
    // race this test will hang or crash under TSan.
    std::atomic<bool> go{false};
    auto worker = [&]() {
        while (!go.load()) { /* spin */ }
        for (int i = 0; i < 200; ++i) {
            rwSession.login(CKU_USER, validPin);
            rwSession.logout();
        }
    };

    std::thread t1(worker);
    std::thread t2(worker);
    go = true;
    t1.join();
    t2.join();
    // No assertion needed — surviving without deadlock is the test.
}