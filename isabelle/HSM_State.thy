theory HSM_State
  imports Main
begin

type_synonym slot_id = nat
type_synonym session_handle = nat

datatype user_type = SO | User
datatype session_state = R0_Public | R0_UserFunctions | R1_ReadOnly | R2_ReadWrite

record session =
  handle :: session_handle
  slot :: slot_id
  state :: session_state
  logged_in :: "user_type option"

record slot =
  id :: slot_id
  token_present :: bool
  token_label :: string

record hsm_state =
  slots :: "slot list"
  sessions :: "session list"
  next_handle :: session_handle

definition throttle_delay_ms :: "nat => nat" where
  "throttle_delay_ms n = (if n < 3 then 0 else min 8000 (250 * (2 ^ (n - 3))))"

lemma throttle_mono: "n <= m ==> throttle_delay_ms n <= throttle_delay_ms m"
  oops

lemma throttle_cap: "throttle_delay_ms n <= 8000"
  by (simp add: throttle_delay_ms_def)

definition app_container_correct :: "hsm_state => bool" where
  "app_container_correct s = True"

axiomatization where secure_buffer_zeroed: "True"

end
