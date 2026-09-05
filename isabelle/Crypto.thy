(* Crypto.thy — crypto primitives
   Mirrors src/crypto/*
*)

theory Crypto
  imports Main
begin

type_synonym key_id = string
type_synonym mechanism = string
type_synonym digest_alg = string
type_synonym payload = "nat list"
type_synonym signature = "nat list"

record sign_result =
  sig_bytes :: signature
  mech_str :: mechanism
  digest :: digest_alg
  payload_digest :: string
  payload_size :: nat

datatype pqc_algo = DILITHIUM2 | DILITHIUM3 | DILITHIUM5 | SPHINCS_SHA256_128s

record pqc_result =
  pqc_algo_field :: pqc_algo
  pqc_sig :: signature
  pqc_fingerprint :: string

definition fips_approved :: "mechanism => bool" where
  "fips_approved m = (m = ''CKM_ECDSA_SHA256'' | m = ''CKM_RSA_PKCS_PSS'' | m = ''CKM_AES_GCM'' | m = ''CKM_SHA256_HMAC'')"

definition mechanism_approved :: "bool => mechanism => bool" where
  "mechanism_approved fips m = (if fips then fips_approved m else True)"

lemma fips_closed: "mechanism_approved True m ==> fips_approved m"
  by (simp add: mechanism_approved_def fips_approved_def)

consts SHA256 :: "payload => string"

axiomatization where
  sha256_deterministic: "SHA256 p = SHA256 p"

consts AES_GCM_Encrypt :: "string => nat list => payload => signature"
consts AES_GCM_Decrypt :: "string => nat list => signature => payload option"

axiomatization where
  aes_gcm_correct: "AES_GCM_Decrypt k iv (AES_GCM_Encrypt k iv pt) = Some pt"

consts Sign :: "key_id => mechanism => payload => sign_result"
consts Verify :: "key_id => mechanism => payload => signature => bool"

axiomatization where
  sign_verify_correct: "Verify kid m p (sig_bytes (Sign kid m p)) = True" and
  sign_deterministic_mech: "mech_str (Sign kid m p) = m"

lemma sign_verify: "Verify kid m p (sig_bytes (Sign kid m p))"
  using sign_verify_correct by simp

consts HMAC :: "string => string => string"

axiomatization where
  hmac_deterministic: "HMAC k s = HMAC k s"

consts HKDF :: "string => string => string"
consts PBKDF2 :: "string => nat list => string"

axiomatization where
  hkdf_injective: "inj (%info. HKDF kek info)"

consts PQC_Sign :: "key_id => pqc_algo => payload => pqc_result"

definition hybrid_sign :: "key_id => key_id => mechanism => pqc_algo => payload => (sign_result * pqc_result option)" where
  "hybrid_sign kid_classic kid_pqc m algo p = (Sign kid_classic m p, (if kid_pqc = '''' then None else Some (PQC_Sign kid_pqc algo p)))"

lemma hybrid_classic_correct:
  "fst (hybrid_sign kid_c kid_p m algo p) = Sign kid_c m p"
  by (simp add: hybrid_sign_def)

definition fips_self_test_pass :: bool where
  "fips_self_test_pass = (fips_approved ''CKM_ECDSA_SHA256'' & fips_approved ''CKM_AES_GCM'')"

lemma fips_self_test: "fips_self_test_pass"
  by (simp add: fips_self_test_pass_def fips_approved_def)

end
