// Throughput benchmark harness — drives the real PKCS#11 C entry points
// end to end (C_Initialize → C_OpenSession → C_InitPIN → C_Login →
// C_GenerateKeyPair → C_SignInit/C_Sign) and reports ops/sec.
//
// Build: cmake -DVHSM_ENABLE_BENCH=ON ... then build target "vhsm_bench" and run it.
//
// Numbers are wall-clock medians of timed batches; the harness is for
// regression tracking (compare before/after a change), not absolute
// hardware claims.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../../../src/pkcs11/pkcs11.h"

namespace {

using Clock = std::chrono::steady_clock;

struct Timer {
  Clock::time_point t0 = Clock::now();
  double stop_ms() const {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
  }
};

void ck_expect(CK_RV rv, const char *what) {
  if (rv != CKR_OK) {
    std::fprintf(stderr, "BENCH FATAL: %s failed with CK_RV=0x%08lx\n", what,
                 static_cast<unsigned long>(rv));
    std::exit(1);
  }
}

// Median-of-runs helper.
template <typename Fn>
double median_ms(int runs, int iters, Fn &&fn) {
  std::vector<double> samples;
  for (int r = 0; r < runs; ++r) {
    Timer t;
    for (int i = 0; i < iters; ++i)
      fn(i);
    samples.push_back(t.stop_ms());
  }
  std::sort(samples.begin(), samples.end());
  return samples[samples.size() / 2];
}

} // namespace

int main() {
  ::setenv("VHSM_DB_PATH", ":memory:", 1);
  ::setenv("VHSM_LEDGER_ENDPOINT", "", 1);

  ck_expect(C_Initialize(nullptr), "C_Initialize");

  CK_SLOT_ID slots[8];
  CK_ULONG n_slots = 8;
  ck_expect(C_GetSlotList(CK_TRUE, slots, &n_slots), "C_GetSlotList");
  if (n_slots == 0) {
    std::fprintf(stderr, "BENCH FATAL: no slots with tokens present\n");
    return 1;
  }

  CK_SESSION_HANDLE h;
  ck_expect(C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          nullptr, 0, &h),
            "C_OpenSession");

  // Init user PIN and log in (ignore already-initialized).
  const char *pin = "1234";
  CK_RV rv = C_InitPIN(h, (CK_UTF8CHAR_PTR)pin, 4);
  if (rv != CKR_OK)
    std::fprintf(stderr, "bench note: C_InitPIN rv=0x%lx (may be pre-set)\n",
                 (unsigned long)rv);
  ck_expect(C_Login(h, CKU_USER, (CK_UTF8CHAR_PTR)pin, 4), "C_Login");

  // ─── EC key generation ────────────────────────────────────────────────
  CK_MECHANISM ec_mech{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_OBJECT_HANDLE pub = 0, priv = 0;
  {
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    static const char curve[] = "P-256";
    CK_ATTRIBUTE pub_tmpl[] = {{CKA_VERIFY, &t, sizeof(t)},
                               {CKA_TOKEN, &f, sizeof(f)},
                               {CKA_EC_PARAMS, (void *)curve,
                                sizeof(curve) - 1}};
    CK_ATTRIBUTE priv_tmpl[] = {{CKA_SIGN, &t, sizeof(t)},
                                {CKA_TOKEN, &f, sizeof(f)}};
    const double gen_ms =
        median_ms(5, 10, [&](int) {
          ck_expect(C_GenerateKeyPair(h, &ec_mech, pub_tmpl, 3, priv_tmpl, 2,
                                      &pub, &priv),
                    "C_GenerateKeyPair");
          C_DestroyObject(h, priv);
          C_DestroyObject(h, pub);
        });
    std::printf("ec_keygen        : %8.3f ms/op   (%d ops sampled)\n",
                gen_ms / 10.0, 50);
  }

  // Persistent signing key for sign/verify benchmarks.
  CK_BBOOL t = CK_TRUE, f = CK_FALSE;
  static const char curve[] = "P-256";
  CK_ATTRIBUTE pub_tmpl[] = {{CKA_VERIFY, &t, sizeof(t)},
                             {CKA_TOKEN, &f, sizeof(f)},
                             {CKA_EC_PARAMS, (void *)curve,
                              sizeof(curve) - 1}};
  CK_ATTRIBUTE priv_tmpl[] = {{CKA_SIGN, &t, sizeof(t)},
                              {CKA_TOKEN, &f, sizeof(f)}};
  ck_expect(C_GenerateKeyPair(h, &ec_mech, pub_tmpl, 3, priv_tmpl, 2, &pub,
                              &priv),
            "C_GenerateKeyPair(setup)");

  // ─── ECDSA sign throughput ────────────────────────────────────────────
  {
    CK_MECHANISM sig_mech{CKM_ECDSA_SHA256, nullptr, 0};
    unsigned char msg[1024];
    for (auto &b : msg)
      b = static_cast<unsigned char>(std::rand());
    unsigned char sig[256];
    CK_ULONG sig_len = sizeof(sig);

    const double sign_ms = median_ms(
        7, 100,
        [&](int) {
          ck_expect(C_SignInit(h, &sig_mech, priv), "C_SignInit");
          sig_len = sizeof(sig);
          ck_expect(C_Sign(h, msg, sizeof(msg), sig, &sig_len), "C_Sign");
        });
    std::printf("ecdsa_sha256_sign: %8.3f ms/op   (%6.0f ops/s)\n",
                sign_ms / 100.0, 100000.0 / sign_ms);

    // Verify once to confirm the pipeline produces valid signatures.
    ck_expect(C_VerifyInit(h, &sig_mech, pub), "C_VerifyInit");
    ck_expect(C_Verify(h, msg, sizeof(msg), sig, sig_len), "C_Verify");
  }

  // ─── SHA-256 digest-only throughput ────────────────────────────────────
  {
    CK_MECHANISM dig_mech{CKM_SHA256, nullptr, 0};
    unsigned char msg[4096], hash[32];
    CK_ULONG hash_len = sizeof(hash);
    for (auto &b : msg)
      b = static_cast<unsigned char>(std::rand());

    const double dig_ms = median_ms(
        7, 200,
        [&](int) {
          ck_expect(C_DigestInit(h, &dig_mech), "C_DigestInit");
          hash_len = sizeof(hash);
          ck_expect(C_Digest(h, msg, sizeof(msg), hash, &hash_len),
                    "C_Digest");
        });
    std::printf("sha256_digest4k  : %8.3f ms/op   (%6.0f ops/s)\n",
                dig_ms / 200.0, 200000.0 / dig_ms);
  }

  // ─── Session open/close churn ──────────────────────────────────────────
  {
    const double sess_ms = median_ms(
        5, 50,
        [&](int) {
          CK_SESSION_HANDLE hs;
          ck_expect(C_OpenSession(slots[0],
                                  CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  nullptr, 0, &hs),
                    "C_OpenSession(churn)");
          ck_expect(C_CloseSession(hs), "C_CloseSession(churn)");
        });
    std::printf("session_churn    : %8.3f ms/pair (%6.0f pairs/s)\n",
                sess_ms / 50.0, 50000.0 / sess_ms);
  }

  C_Logout(h);
  C_CloseSession(h);
  C_Finalize(nullptr);
  std::printf("\nbench done.\n");
  return 0;
}
