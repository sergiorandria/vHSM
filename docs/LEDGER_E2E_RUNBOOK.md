# Ledger End-to-End Runbook (vHSM → Hyperledger Fabric)

Minimal path to get a `C_Sign` performed through the vHSM PKCS#11 module
anchored immutably on Fabric via the `signature_ledger` chaincode. Companion
docs: `FABRIC_CHAINCODE.md` (architecture), `network/fabric_configuration/NEW_CHAINCODE.md`
(chaincode lifecycle reference).

## Prerequisites

- Docker + Docker Compose, the `peer` CLI, Fabric CA tooling
- Go 1.26 (chaincode build), cmake + a C++23 toolchain (vHSM build)
- The vHSM build dependencies (see top-level `README.md` / `CHANGELOG.md`)

## 1. Bring up the Fabric network

```bash
cd network/fabric_configuration/fabric-network
./generate-network.sh
./enroll-network.sh
# creates orgs, MSPs, the CA, orderer and peers
```

> **Channel name is fixed on the C++ side.** `LedgerClient` hard-codes
> `getNetwork("signaturechannel")` and `getContract("signature_ledger")`
> (`src/ledger/ledger_client.cpp:86,90`). Make sure a channel named
> **`signaturechannel`** exists (adjust `configtx.yaml` / the create-channel
> step if the network scripts default to another name such as `canaltest`).

## 2. Build & deploy the `signature_ledger` chaincode

The chaincode runs as CCaaS (it expects `CORE_CHAINCODE_ID_NAME` +
`CHAINCODE_SERVER_ADDRESS`; `main.go` sets the contract name to
`signature_ledger`).

```bash
cd network/fabric_configuration/signature_ledger
docker build -t signature-ledger-ccaas:1.0 -f Dockerfile .
```

Then package / install / approve / commit following the CCaaS pattern in
`NEW_CHAINCODE.md`, with these identities:

- **name:** `signature_ledger`
- **channel:** `signaturechannel`
- **CCaaS env:** `CORE_CHAINCODE_ID_NAME=signature_ledger:<PKG_ID>`,
  `CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999`

```bash
peer lifecycle chaincode package signature_ledger.tar.gz \
  --lang golang --label signature_ledger_1.0
peer lifecycle chaincode install signature_ledger.tar.gz
peer lifecycle chaincode queryinstalled            # copy the Package ID

peer lifecycle chaincode approveformyorg \
  -o orderer.university.com:7050 --channelID signaturechannel \
  --name signature_ledger --version 1.0 --sequence 1 \
  --package-id signature_ledger:<PKG_ID> --tls --cafile $ORDERER_CA

peer lifecycle chaincode commit \
  -o orderer.university.com:7050 --channelID signaturechannel \
  --name signature_ledger --version 1.0 --sequence 1 \
  --peerAddresses peer0.misa.university.com:7051 \
  --tlsRootCertFiles $PEER_CA --tls --cafile $ORDERER_CA
```

## 3. Build vHSM with ledger support

```bash
cmake -S . -B build-ledger -DVHSM_STORE_BACKEND=db -DVHSM_BUILD_EXAMPLES=ON -DVHSM_LEDGER=ON
cmake --build build-ledger -j
# module: build-ledger/src/pkcs11/libvhsm_pkcs11.so
```

`-DVHSM_LEDGER=ON` compiles the ledger code. Anchoring is actually switched on
at **runtime** (next step).

## 4. Configure the runtime (env)

```bash
export VHSM_DB_PATH=:memory:            # or a file path for a durable audit store
export VHSM_STORE_BACKEND=ledger        # enables anchoring (Fabric = source of truth)
export VHSM_LEDGER_ENDPOINT=127.0.0.1:7051
export VHSM_LEDGER_CERT=$CRYPTO_PATH/peerOrganizations/misa.university.com/users/User1@misa.university.com/msp/signcerts/User1@misa.university.com-cert.pem
export VHSM_LEDGER_KEY=$CRYPTO_PATH/peerOrganizations/misa.university.com/users/User1@misa.university.com/msp/keystore/<key>
export VHSM_LEDGER_CA=$CRYPTO_PATH/peerOrganizations/misa.university.com/peers/peer0.misa.university.com/tls/ca.crt
export VHSM_LEDGER_MSP_ID=MisaMSP
```

mTLS is **fail-closed**: empty `VHSM_LEDGER_CERT`/`KEY` makes `LedgerClient`
throw (`ledger_client.cpp:52`). If the env is absent, signing still works but
**nothing is anchored**.

## 5. Sign → anchor

Initialize a token and generate a signing key once (examples
`ex01_init_and_login`, `ex02_generate_keys`), then run a sign op against the
ledger-enabled module:

```bash
./build-ledger/examples/pkcs11/ex01_init_and_login
./build-ledger/examples/pkcs11/ex02_generate_keys
./build-ledger/examples/pkcs11/ex03_sign_verify
```

With `VHSM_STORE_BACKEND=ledger` + the `VHSM_LEDGER_*` vars set, every
`C_Sign` is persisted locally and anchored asynchronously to
`signature_ledger` through the outbox → poller → retry-queue → `LedgerWorker`
pipeline (see Appendix A).

## 6. Verify on-chain

```bash
peer chaincode query -C signaturechannel -n signature_ledger \
  -c '{"Args":["GetRecord","<record_id>"]}'
```

Expect JSON with `tx_id` and `block_number` (field names in
`chaincode.go`). From C++, call `LedgerClient::get_record(record_id)`.

## Appendix A — `C_Sign` → ledger call path

```text
C_Sign                              src/pkcs11/p11_crypto.cpp:969
  └─ do_sign                        p11_crypto.cpp:294   (RSA/ECDSA signature)
  └─ dispatch_sign_result           p11_crypto.cpp:582   (builds sign_result + created_at)
       └─ SignatureDispatcher::dispatch
            └─ v_SignatureDispatcherCore_M1::v_dispatch
                 src/signature_store/internal/signature_dispatcher_core.cpp
                 • writes signature record + event_outbox row (PENDING) atomically
       OutboxPoller                 → publishes SIGN_CREATED
       LedgerRetryQueue             → load_pending_records() (replays PENDING on startup)
       LedgerWorker::submit_record  → process_record (retry/backoff)
         └─ LedgerClient::submit_record   src/ledger/ledger_client.cpp:110
              └─ contract_->submitTransaction("RecordSignature", …)  → Fabric commit
                 returns tx_id + block_number
                 → on_committed_ updates local DB + publishes LEDGER_COMMITTED
```

DB-write failure is deliberately swallowed at the C ABI
(`p11_crypto.cpp:643`) so a ledger outage never fails `C_Sign`; ledger
failures surface via `LEDGER_COMMIT_FAILED` + PENDING replay instead.

## Appendix B — Resilience & observability

- **Fail-closed mTLS** — absent cert/key ⇒ no anchoring (silent), never an
  insecure downgrade.
- **Retries** — `LedgerWorker::process_record` backs off exponentially;
  exhausted ⇒ row stays `PENDING` and is replayed by `LedgerRetryQueue` on the
  next `C_Initialize` (`composition_root.cpp:389`).
- **Notifications** — `LEDGER_COMMITTED` / `LEDGER_COMMIT_FAILED` events on the
  `NotificationBus`.
- **Local trail** — `vhsm_ledger.sqlite` stores the record plus
  `ledger_tx_id` / `block` / `status`, updated by the `on_committed_` callback.

## Appendix C — The Go REST API alternative

The REST API (`rest_api/`) can anchor through the *same* contract by setting
`CHAINCODE_NAME=signature_ledger` and `CHANNEL_NAME=signaturechannel` in
`.env`. Its `HSM_MODULE_PATH` selects the PKCS#11 backend (SoftHSM2 or the
vHSM C++ module) — see `FABRIC_CHAINCODE.md`.
