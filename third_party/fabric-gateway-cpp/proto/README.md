# Vendored fabric-protos

Snapshot of the Hyperledger Fabric protocol definitions used to generate the
C++ gRPC stubs in `fabric-proto`.

- **Source:** https://github.com/hyperledger/fabric-protos
- **Branch:** `main`
- **Commit:** `1acd42dcccd0d50e9148631d371ad7e470469123`

All 38 `.proto` files under `common/`, `peer/`, `msp/`, `ledger/`,
`orderer/`, `gateway/` are vendored verbatim.  `protoc` + `grpc_cpp_plugin`
(code-generated at build time) produce the Gateway service
(`gateway/gateway.proto`), the peer Deliver service (`peer/events.proto`) and
the orderer AtomicBroadcast service (`orderer/ab.proto`) alongside the
plain-message stubs.

Upgrade by re-snapshoting from upstream and updating the commit above.