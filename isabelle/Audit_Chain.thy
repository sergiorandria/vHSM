theory Audit_Chain
  imports Main
begin

type_synonym seq = nat
type_synonym timestamp = nat
type_synonym event_id = string
type_synonym event_type = string
type_synonym hash = string
type_synonym chain_key = string

record audit_record =
  seq :: seq
  ts :: timestamp
  eid :: event_id
  etype :: event_type
  prev :: hash
  hmac :: hash

type_synonym chain = "audit_record list"

consts HMAC_SHA256 :: "chain_key => string => hash"
axiomatization where hmac_injective_key: "inj (%k. HMAC_SHA256 k s)"

definition record_bytes :: "audit_record => string" where
  "record_bytes r = eid r @ etype r @ prev r"

definition recompute_hmac :: "chain_key => audit_record => hash" where
  "recompute_hmac k r = HMAC_SHA256 k (record_bytes r)"

definition empty_hash :: hash where "empty_hash = ''0''"

fun append_record :: "chain_key => chain => event_id => event_type => timestamp => chain" where
  "append_record k [] eid0 etype0 ts0 = [(| seq = 1, ts = ts0, eid = eid0, etype = etype0, prev = empty_hash, hmac = HMAC_SHA256 k (eid0 @ etype0 @ empty_hash) |)]"
| "append_record k chain eid0 etype0 ts0 = chain @ [(| seq = Suc (length chain), ts = ts0, eid = eid0, etype = etype0, prev = empty_hash, hmac = HMAC_SHA256 k (eid0 @ etype0 @ empty_hash) |)]"

definition tail_hash :: "chain => hash" where
  "tail_hash c = (if c = [] then empty_hash else hmac (last c))"

fun verify_chain :: "chain_key => chain => nat option" where
  "verify_chain k [] = None"
| "verify_chain k (r # rs) = (if recompute_hmac k r ~= hmac r then Some (seq r) else verify_chain k rs)"

definition chain_valid :: "chain_key => chain => bool" where
  "chain_valid k c = (verify_chain k c = None)"

lemma append_preserves_valid:
  assumes "chain_valid k c"
  shows "chain_valid k (append_record k c eid0 etype0 ts0)"
  oops

end
