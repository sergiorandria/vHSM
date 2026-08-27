# Fabric Chaincode & HSM Backend — Contributor Guide

vHSM can anchor signatures (and other records) to a Hyperledger Fabric
ledger. There are **two chaincodes** and **two clients**, plus a **choice of
HSM backend** for the Go REST API. This document explains how they fit
together so contributors can extend them without guessing.

## Two chaincodes, two clients

| Chaincode dir | Contract name | Channel | Consumed by | Purpose |
|---|---|---|---|---|
| `network/fabric_configuration/signature_ledger/` | `signature_ledger` | `signaturechannel` | **C++ `LedgerClient`** (`src/ledger/ledger_client.cpp`) | Anchor HSM-generated signatures |
| `network/fabric_configuration/template_chaincode/` | `template_chaincode` (`ThesisContract`) | `canaltest` | **Go REST API** (`rest_api/`, via `.env.example`) | Generic CRUD scaffold |

They are **not duplicates**. The C++ PKCS#11 core (`libvhsm_pkcs11.so`) and
the Go REST API are two separate front-ends; each talks to its own contract
on its own channel. The contract name and channel are hard-coded on the
client side, so they must match the deployed chaincode:

- C++ client → `getContract("signature_ledger")` on `getNetwork("signaturechannel")`.
- Go REST API → `CHAINCODE_NAME=template_chaincode` / `CHANNEL_NAME=canaltest` (`.env.example`).

### `signature_ledger` (C++ path)

Implements `SignatureLedger` with two methods:

- `RecordSignature(recordID, keyFingerprint, payloadDigest, signatureB64, createdAt)`
  — commits one anchored signature record.
- `GetRecord(recordID)` — returns the anchored record.

The on-chain JSON fields are
`record_id`, `key_fingerprint`, `payload_digest`, `signature_b64`,
`created_at`, `tx_id`, `block_number` — these **must stay in sync** with the
C++ parser in `src/ledger/ledger_client.cpp`.

### `template_chaincode` (Go REST API path)

Implements `ThesisContract`, a generic CRUD template (`chaincode.go`). It is a
starting scaffold; if you extend the Go REST API to anchor signatures, point
`CHAINCODE_NAME` at `signature_ledger` (and reuse `RecordSignature`/`GetRecord`)
rather than inventing a second anchoring contract.

## Building a chaincode

```bash
cd network/fabric_configuration/<dir>
go build ./...        # compiles; the resulting binary is gitignored — do NOT commit it
go vet ./...
```

Each dir has a `Dockerfile` for packaging as a CCaaS (chaincode-as-a-service)
image.

## Deploying

Use the standard Fabric lifecycle (`peer lifecycle chaincode
package/install/approve/commit`). See
`network/fabric_configuration/README.md` and `NEW_CHAINCODE.md`. The only
vHSM-specific requirement is that the **channel name matches the client**:

- `signature_ledger` → channel `signaturechannel`
- `template_chaincode` → channel `canaltest`

## Choosing the HSM backend (Go REST API)

The Go REST API loads a PKCS#11 shared library via `HSM_MODULE_PATH`
(`rest_api/.env.example`, read in `rest_api/cmd/api/main.go`). Both backends
are supported — pick one:

| Backend | `HSM_MODULE_PATH` value | Use |
|---|---|---|
| **SoftHSM2** | `/usr/lib/softhsm/libsofthsm2.so` | Dev / tests |
| **vHSM C++ module** | `<build>/src/pkcs11/libvhsm_pkcs11.so` | Production |

The vHSM C++ module **is** the PKCS#11 library built by the main project
(`cmake -S . -B build -DVHSM_LEDGER=ON` → `build/src/pkcs11/libvhsm_pkcs11.so`).
Pointing the Go REST API at it lets the API sign through the same vHSM core
used by the C++ path.

Requirements for either backend:

- A token labelled by `HSM_TOKEN_LABEL` (default `vhsm-token`).
- An AES secret key with label `HSM_LABEL` (default `vhsm-aes-key`).
- A private signing key with label `HSM_SIGN_LABEL` (default `vhsm-sign-key`).

The C++ client itself always uses the vHSM module (it *is* the module); the
backend choice above only affects the Go REST API.

## End-to-end smoke test (C++ path)

1. Bring up the network: `network/fabric_configuration/fabric-network/{generate-network.sh, enroll-network.sh}` (name the channel **`signaturechannel`**).
2. Build + package `network/fabric_configuration/signature_ledger/` as a CCaaS image; `peer lifecycle chaincode` install/approve/commit it on `signaturechannel`.
3. Build vHSM: `cmake -S . -B build -DVHSM_STORE_BACKEND=ledger -DVHSM_LEDGER=ON`, configure the gateway connection + mTLS (fail-closed).
4. Run a `C_Sign` (it anchors to the ledger) and exercise `tests/integration/*` + `tests/rest_api/*`.

> Note: the third-party `fabric-gateway-cpp` submodule ships its own
> `fabric_gateway_cpp_gateway_tests`, which require a live Fabric peer and
> are expected to fail in CI. They are not part of vHSM's test suite.
