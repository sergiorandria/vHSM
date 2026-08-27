// 01 — Minimal vHSM lifecycle: C_Initialize → slot → session → login → logout
//
// Build (from repo root, after `cmake --preset linux-ninja && cmake --build build`):
//   g++ -std=c++23 examples/pkcs11/01_init_and_login.cpp -I src -L build -lvhsm_pkcs11 -lcrypto -o /tmp/ex01 && /tmp/ex01
// Or via CMake: cmake -S . -B build -DVHSM_BUILD_EXAMPLES=ON && cmake --build build --target ex01_*

#include <cstdio>
#include <cstdlib>

#include "pkcs11/pkcs11.h"

static void ck(const char *what, CK_RV rv) {
  if (rv != CKR_OK) {
    std::fprintf(stderr, "%s failed: 0x%08lx\n", what, (unsigned long)rv);
    std::exit(1);
  }
}

int main() {
  ::setenv("VHSM_DB_PATH", ":memory:", 1);

  ck("C_Initialize", C_Initialize(nullptr));

  CK_SLOT_ID slots[8];
  CK_ULONG n = 8;
  ck("C_GetSlotList", C_GetSlotList(CK_TRUE, slots, &n));
  std::printf("found %lu slot(s) with token\n", (unsigned long)n);

  CK_SESSION_HANDLE h;
  ck("C_OpenSession",
     C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, 0, &h));
  std::printf("session %lu opened\n", (unsigned long)h);

  // First run: user PIN not yet set — C_InitPIN sets it to "1234".
  CK_RV rv = C_InitPIN(h, (CK_UTF8CHAR_PTR) "1234", 4);
  if (rv != CKR_OK)
    std::printf("C_InitPIN: 0x%08lx (already set?)\n", (unsigned long)rv);

  ck("C_Login", C_Login(h, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4));
  std::printf("logged in as CKU_USER\n");

  ck("C_Logout", C_Logout(h));
  ck("C_CloseSession", C_CloseSession(h));
  ck("C_Finalize", C_Finalize(nullptr));
  std::printf("done.\n");
}
