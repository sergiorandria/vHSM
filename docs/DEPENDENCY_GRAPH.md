# vHSM Dependency Graph

How the vHSM modules, third-party submodules, and external consumers depend on
each other. Two views:

1. **Build/module graph** — C++ `add_library` targets and their
   `target_link_libraries` edges (from `src/*/CMakeLists.txt`).
2. **System/runtime graph** — the loadable `.so`, the Go REST API, the Fabric
   chaincode, and the two git submodules.

> Edges marked `VHSM_LEDGER` are compiled in **only** when CMake is configured
> with `-DVHSM_LEDGER=ON` (the Fabric anchoring path).

## 1. Build / module dependency graph

```mermaid
graph TD
  core["vhsm_core<br/>(leaf: secure_buffer, hsm_instance, clocks)"]
  log["vhsm_log"]
  tp["vhsm_threadpool"]
  notif["vhsm_notification"]
  prov["vhsm_crypto_provider<br/>(submodule: vhsm-secure-crypto)"]
  crypto["vhsm_crypto<br/>(RSA/ECC/AES-GCM/...)"]
  keystore["vhsm_keystore"]
  session["vhsm_session<br/>(LoginThrottle)"]
  persist["vhsm_persistence<br/>(vault, KDF, serializer)"]
  sig["vhsm_signature_store<br/>(embeds audit_log.cpp)"]
  ledger["vhsm_ledger<br/>(LedgerClient + LedgerWorker)"]
  fgw["fabric-gateway-cpp<br/>(submodule)"]
  admin["vhsm_admin<br/>(gRPC service)"]
  pkcs11["vhsm_pkcs11 / vhsm_pkcs11_mod<br/>(loadable .so)"]

  log --> core
  tp --> log
  notif --> core
  crypto --> prov
  keystore --> core
  keystore --> prov
  session --> core
  session --> prov
  persist --> core
  persist --> crypto
  persist --> keystore
  persist --> prov
  sig --> core
  sig --> crypto
  sig --> keystore
  sig --> persist
  sig --> notif
  sig --> prov
  ledger --> fgw
  admin --> core
  admin --> keystore
  admin --> persist
  admin --> session
  admin --> notif
  admin --> sig
  pkcs11 --> core
  pkcs11 --> log
  pkcs11 --> crypto
  pkcs11 --> keystore
  pkcs11 --> persist
  pkcs11 --> session
  pkcs11 --> sig
  pkcs11 --> notif
  pkcs11 --> tp
  pkcs11 --> prov
  pkcs11 -. "VHSM_LEDGER" .-> ledger
  sig -. "VHSM_LEDGER" .-> ledger
```

Notes:
- `vhsm_core` is the root leaf (no internal deps; links `bcrypt` only on
  Windows, and transitively OpenSSL via `vhsm_crypto_provider`).
- **Audit** is *not* a separate library: `src/audit/audit_log.cpp` is compiled
  directly into `vhsm_signature_store` (`src/signature_store/CMakeLists.txt:18`),
  so the hash-chained audit log is part of the signature store.
- `vhsm_pkcs11` is built both as an OBJECT lib and as the shared module
  `vhsm_pkcs11_mod` (the PKCS#11 `.so`); both share the same link set.
- `vhsm_admin` adds `protobuf::libprotobuf` + `gRPC::grpc++` (proto codegen from
  `hsm_admin.proto`).

## 2. System / runtime dependency graph

```mermaid
graph TD
  subgraph vHSM_Cpp["vHSM C++ (this repo)"]
    pkcs11["vhsm_pkcs11.so"]
    admin["vhsm_admin (gRPC server)"]
  end

  subgraph Submodules["git submodules"]
    vsc["third_party/vhsm-secure-crypto<br/>→ vhsm_crypto_provider"]
    fgw["third_party/fabric-gateway-cpp<br/>→ gRPC/protobuf/OpenSSL"]
  end

  subgraph SystemLibs["system / third-party libs"]
    ssl["OpenSSL"]
    sql["SQLite3"]
    grpc["gRPC + protobuf"]
    json["nlohmann_json"]
  end

  subgraph Consumers["consumers"]
    restapi["Go REST API (rest_api/)"]
    examples["PKCS#11 examples ex01..ex06"]
    bench["vhsm_bench"]
    chaincode["signature_ledger chaincode (Go)"]
    fabric["Hyperledger Fabric<br/>(docker/ · real-network/)"]
  end

  pkcs11 --> vsc
  pkcs11 --> fgw
  pkcs11 --> sql
  pkcs11 --> json
  admin --> pkcs11
  admin --> grpc
  restapi -->|"loads HSM_MODULE_PATH"| pkcs11
  examples --> pkcs11
  bench --> pkcs11
  pkcs11 -->|"anchors (RecordSignature)"| chaincode
  restapi -->|"invokes"| chaincode
  chaincode --> fabric
  fgw --> grpc
  fgw --> ssl
  vsc --> ssl
```

Notes:
- The C++ core is a **library** (`libvhsm_pkcs11.so`) loaded by PKCS#11
  consumers. The Go REST API points `HSM_MODULE_PATH` at it and also talks to
  the same Fabric chaincode (`signature_ledger`) that `vhsm_ledger` anchors to.
- `vhsm-secure-crypto` and `fabric-gateway-cpp` are **pinned git submodules**
  under `third_party/` — remember to push the submodule before the superproject
  (see `docs/FABRIC_CHAINCODE.md`, "Submodules and the push workflow").
- `vhsm_bench` and the `examples/pkcs11` executables link the same `.so`.

## How to regenerate / verify

The graph above is derived from the `target_link_libraries` calls in
`src/*/CMakeLists.txt`. To re-check after build changes:

```bash
rg -n "target_link_libraries\(" --glob 'CMakeLists.txt' src -A6
```

Or render the Graphviz version (`docs/dependency_graph.dot`) with:

```bash
dot -Tsvg docs/dependency_graph.dot -o dependency_graph.svg
```
