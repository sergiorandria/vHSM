(* VHSM.thy — Virtual HSM Correctness: Root Theory *)

theory VHSM
  imports
    Audit_Chain
    HSM_State
    Crypto
    Ledger
    Main
begin

text \<open>
Virtual HSM — correctness root. Architecture: docs/ARCHITECTURE_REVIEW.md
Jury → Go REST API → SoftHSM PKCS#11 → vHSM .so (C_Sign) → SignatureDispatcher
→ event_outbox (db_schema.h v6) → OutboxPoller → BoundedNotificationBus
→ Email/Webhook/gRPC/MobilePush → ISignatureStore (Db/ Fabric) → SQLite or Fabric.
\<close>

locale vhsm =
  fixes chain_key :: "string => string"
  and pqc_enabled :: bool
  and fips_enabled :: bool
  and ledger_enabled :: bool
  assumes chain_key_injective: "inj chain_key"
    and fips_implies_approved_mech: "fips_enabled ==> (!m. fips_approved m)"
  notes chain_key_injective

theorem vhsm_sign_correct:
  assumes "chain_key_injective"
  shows "True"
  oops

text \<open>
How to check: isabelle build -D isabelle
\<close>

end
