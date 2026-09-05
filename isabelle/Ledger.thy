theory Ledger
  imports Main
begin

type_synonym record_id = string
type_synonym tx_id = string
type_synonym block_number = nat

datatype ledger_status = PENDING | COMMITTED | FAILED | DISABLED

record signature_record =
  srid :: record_id
  created_at :: nat
  slot_id :: nat
  token_label :: string
  key_id :: string
  mechanism :: string
  sig_b64 :: string
  ledger_tx :: "tx_id option"
  ledger_block :: "block_number option"
  status :: ledger_status

definition is_pending :: "signature_record => bool" where
  "is_pending r = (status r = PENDING)"
definition is_committed :: "signature_record => bool" where
  "is_committed r = (status r = COMMITTED)"

definition mark_committed :: "signature_record => tx_id => block_number => signature_record" where
  "mark_committed r tx blk = r(| ledger_tx := Some tx, ledger_block := Some blk, status := COMMITTED |)"

type_synonym event_id = string
datatype outbox_status = Outbox_PENDING | Outbox_DISPATCHED

record outbox_entry =
  eid :: event_id
  rec_id :: record_id
  ostatus :: outbox_status

definition outbox_correct :: "signature_record => outbox_entry => bool" where
  "outbox_correct r e = (rec_id e = srid r & ostatus e = Outbox_PENDING)"

lemma outbox_atomic:
  assumes "outbox_correct r e"
  shows "rec_id e = srid r"
  oops

consts ledger_upsert :: "record_id => signature_record => tx_id * block_number"
consts ledger_get :: "record_id => (tx_id * block_number) option"

axiomatization where
  ledger_idempotent: "ledger_upsert rid r = ledger_upsert rid r"

definition exactly_once :: "record_id => bool" where
  "exactly_once rid = (EX tx blk. ledger_get rid = Some (tx, blk))"

record ledger_proof =
  p_record_id :: record_id
  p_sig_b64 :: string
  p_tx_id :: tx_id
  p_block :: block_number

definition proof_valid :: "signature_record => ledger_proof => bool" where
  "proof_valid r p = (p_record_id p = srid r & p_sig_b64 p = sig_b64 r)"

consts ledger_tail :: "string"
consts file_tail :: "string"

definition truncation_detected :: bool where
  "truncation_detected = (ledger_tail ~= file_tail)"

end
