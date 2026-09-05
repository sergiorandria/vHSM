# vHSM — 10-Minute Jury Demo Runbook

**Goal:** Show jury a live thesis lifecycle (HSM sign → Fabric anchor → audit + mobile push) with zero CLI.

**Prereqs (once):** `cmake --preset linux-ninja && cmake --build build -j4 && ctest --test-dir build -j4` (310/310), `cd rest_api && go mod download`, `cd web && npm install && npm run build`, Fabric material in `/etc/vhsmd` or `network/fabric_configuration/docker`.

---

## 0. Start Stack (1 min)

```bash
# terminal 1: REST API (serves SPA at /)
cd rest_api
JWT_SECRET=dev-secret MINIO_ENDPOINT=localhost:9000 MINIO_ACCESS_KEY=minioadmin MINIO_SECRET_KEY=minioadmin \
HSM_MODULE_PATH=/usr/lib/libvhsm.so HSM_TOKEN_LABEL=MyToken HSM_PIN=1234 \
go run ./cmd/api  # :8080, serves web/dist at /

# terminal 2: tail logs
curl -s http://localhost:8080/api/v1/fabric/status | jq .  # should return orderer/peers/channels once Fabric up
```

Open `http://localhost:8080/` → **vHSM Fabric Console** (blue/techno, JWT bar top).

## 1. Auth (30s)

```bash
curl -X POST http://localhost:8080/api/v1/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq
# copy token → paste in JWT bar → ● connected
```

*Why:* All `/api/v1/*` require `Bearer` + RBAC (`rest_api/cmd/api/main.go:364` `authRequired`, `392` `requirePermission`). Show 401 without token, then 200.

## 2. Fabric Control Console — Builder (2 min)

**Tab: Builder**

* Orderer `university.com` + 1 org `misa` (2 peers) + channel `canaltest` prefilled — replicas of `network/fabric_configuration/docker/generate-network.sh` + `enroll-network.sh`.
* Click **Generate network (write network.env)** → `POST /api/v1/fabric/network` `rest_api/internal/fabric_manager.go:120` writes `network.env`.
* Click **▶ Deploy & Auto-Join** → `POST /api/v1/fabric/deploy` `fabric_manager.go:180` starts async job: `docker compose up` → `peer channel join` → `chaincode install/approve/commit` (steps auto).
* **DeployOverlay** shows `Synchronizing Fabric Network 0→100%` with steps `✓/◐/○`, pulse + progress bar `web/src/App.jsx:45`. Peers auto-join; no manual `peer channel join` needed.

Poll `GET /fabric/jobs/:id` drives overlay; `GET /fabric/status` refreshes topology.

## 3. Dashboard — Topology (1 min)

**Tab: Dashboard**

* KPI grid `web/src/App.jsx:86` + `styles.css:71`: Orderer `university.com:7050` `etcdraft`, Peers `4/4 online`, Ledger `#{lastBlock}`, Chaincodes `template_chaincode,signature_ledger`.
* **Network Topology** `App.jsx:96`: orderer ♦ → orgs `misaMSP` → peers `peer0:7051`/`peer1:7053` with `● running`.
* **Channel Map** `App.jsx:121`: `canaltest`/`signaturechannel` heights + chaincode versions.

Point to `src/pkcs11/composition_root.cpp:104` fallback `/etc/vhsmd` vs `network/.../Conf_with_fabric-CA`.

## 4. Thesis Lifecycle — Jury Consensus (2 min)

**Use Go API directly (or via web Thesis tab):**

```bash
# superadmin creates thesis (DRAFT)
curl -X POST http://localhost:8080/api/v1/theses -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"thesisID":"t-demo","studentID":"s-001","student":{"name":"Alice"},"administrative":{"juryMembers":["jury1","jury2","jury3"]},"metadata":{}}'

# jury1 grades
curl -X POST http://localhost:8080/api/v1/theses/t-demo/grades -H "Authorization: Bearer $JURY1_TOKEN" -d '{"grade":"A","comment":"Excellent"}'
# repeat jury2, jury3 → status flips DRAFT→DEFENDED (chaincode enforces quorum, not API)
curl http://localhost:8080/api/v1/theses/t-demo/jury-status -H "Authorization: Bearer $TOKEN" | jq
```

Show `chaincode.go:95` state machine + PV hash immutability: first `SignPv` with file sets `HashPv`; later signers sign same hash (mismatch → 409).

## 5. HSM Sign → Fabric Anchor (1 min)

**Tab: vHSM Sign** `App.jsx:463` — `🔐 Sign with vHSM`

* Paste `Hello vHSM — sign this thesis digest.` → **Sign with vHSM** → `POST /api/v1/fabric/sign` `main.go:891` `fabricMgr.SignWithHSM` → `C_Sign` `src/pkcs11/p11_crypto.cpp:398` (`#ifdef VHSM_LEDGER` policy) → `FabricStoreAdapter` → `LedgerClient::submit_record` → `signature_ledger` `RecordSignature` (idempotent, `LedgerWorker` exactly-once).
* Response shows `algorithm`, `payloadHash` `SHA-256`, `signature` hex+b64. New row appears in **Live Transactions** within 4s poll.

Lead to **Verify** tab: paste returned `record_id` → `GET /api/v1/proof/:recordId` `main.go:743` → `signature_ledger.GetRecord` proof (`tx_id`, `block_number`, `key_fingerprint`).

## 6. Live Transactions + Audit Tamper (2 min)

**Tab: Live Transactions** `App.jsx:293` — polls `GET /fabric/transactions?limit=50` every 4s, also SSE `GET /transactions/stream` `main.go:834`. Click row → drawer shows `txId`, `channel`, `chaincode:function`, `endorser`, `payloadHash`, `blockNumber`, validation `VALID`.

**Tab: Audit** `App.jsx:394`

* Shows `✓ No tamper` + `Verify integrity now` `POST /fabric/audit/verify` `fabric_manager.go: VerifyAudit()` → `src/audit` HMAC chain walk + `VerifyIntegrity` ledger cross-check.
* Click **Simulate tamper** `POST /fabric/audit/simulate-tamper` → `🚨 TAMPER DETECTED` red pulse `styles.css:130` + `409` + timeline `SEQ|TS|TAIL` diverges from ledger anchor. Click **Clear simulation** → back to `✓`.

## 7. Mobile Push (30s)

Show `mobile/` Expo app (or emulator): **Login** → JWT, **Thesis** tab, **Notifications** `mobile/src/services/push.ts:1` registers `POST /api/v1/mobile/devices` `main.go:909` `mobileSvc.Register`. C++ `MobilePushAdapter` `src/notification/mobile_push_adapter.cpp:1` fans out via `internal/mobile_service.go`. Even without FCM, **GET /mobile/notifications** polling fallback aggregates `GetThesisHistory` into inbox.

## 8. Wrap (30s)

* Tests: `ctest 310/310` `6.73s`, `go vet 0`, `npm build 909ms`, `fabric-gateway-cpp:e5adfad` clean.
* Architecture: `src/domain/signing/isignature_store.h:16` port, `AppContainer` `composition_root.h:40` + `pal.h:23` `mlock`/`VirtualLock`, `event_outbox` `db_schema.h:15` v6, `CHANGELOG.md:1` `1.3.0`.
* Repo: `origin/master` `75732c5` (95%→98%) + `origin/dev` synced, `rest_api/README.md:1` professional, `docs/VHSM_PROJECT_COMPLETION_STATUS.md:1` updated.

**Leave jury on `http://localhost:8080/` Dashboard — topology live, last block ticking.**

---

*Runbook mirrors `docs/LEDGER_E2E_RUNBOOK.md` + `network/fabric_configuration/docker/README.md` for Fabric CA flow. All endpoints require `ReadThesis` minimum; mutations need `CreateThesis`/`SignPv`.*
