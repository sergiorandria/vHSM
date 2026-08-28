# Real-network topology example: local machine + internet machine

This document shows one concrete split. Replace the example names/IPs with
yours.

## Machines

| Machine | Location | Runs | Public address |
|---|---|---|---|
| `host-a` | Local LAN / same machine | Orderer + Org1 peer + Org1 CA | `org1.example.com` (LAN: `192.168.1.10`) |
| `host-b` | Internet VM | Org2 peer + Org2 CA | `org2.example.com` (public IP `203.0.113.20`) |

The two machines are NOT on the same Docker network. They reach each other
over the internet (or a VPN) using their **public DNS/IP**.

## Gossip / discovery across hosts

Fabric peers discover each other via gossip. For cross-host gossip to work:

1. Each peer's `CORE_PEER_GOSSIP_EXTERNALENDPOINT` must be its **public**
   address (`org1.example.com:7051` on host-a, `org2.example.com:7051` on
   host-b), NOT the container name.
2. `AnchorPeers` in `configtx.yaml` must list the public host:port for each
   org so the two orgs can bootstrap gossip across the internet.
3. The orderer's consenter address in `configtx.yaml` is
   `org1.example.com:7050` (host-a's public address).

## TLS

Every TLS certificate must include the **public hostname** as a SAN:

- `peer0.org1` cert SAN: `peer0.org1.example.com`, `org1.example.com`,
  `192.168.1.10` (and `localhost` for local testing).
- `peer0.org2` cert SAN: `peer0.org2.example.com`, `org2.example.com`,
  `203.0.113.20`.
- orderer cert SAN: `orderer.university.com`, `org1.example.com`.

If you use `../docker/generate-network.sh` to mint certs, edit its `csr.hosts`
list (in `generate_ca_and_ldap_config`) to add the public hostname before
generating.

## Firewall / ports to open

On each host, allow inbound:

| Port | Service |
|---|---|
| 7050 | Orderer (host-a only) |
| 7051 | Peer chaincode endorse/query |
| 7052 | Peer chaincode server (CCaaS) |
| 7053 | Peer operations / admin (restrict!) |
| 17054 / 18054 | Fabric-CA operations (restrict to LAN) |
| 5432 / 1389 | PostgreSQL / OpenLDAP (restrict to LAN / not public) |

Do **not** expose PostgreSQL/LDAP/CA-operations to the internet; keep them on
the LAN or behind a VPN.

## Client (vHSM) wiring

On host-a, the vHSM C++ module is configured (e.g. via env / systemd) as:

```
VHSM_STORE_BACKEND=ledger
VHSM_LEDGER_ENDPOINT=org1.example.com:7051
VHSM_LEDGER_MSP_ID=Org1MSP
VHSM_LEDGER_CERT=/etc/vhsmd/organizations/.../Admin@org1.example.com/tls/client.crt
VHSM_LEDGER_KEY=/etc/vhsmd/organizations/.../Admin@org1.example.com/tls/client.key
VHSM_LEDGER_CA=/etc/vhsmd/organizations/.../peer0.org1.example.com/tls/ca.crt
VHSM_LEDGER_SERVER_NAME=peer0.org1.example.com
```

The Go REST API uses the same values via `rest_api/.env.example`
(`CHAINCODE_NAME`, `CHANNEL_NAME`, and the gateway connection profile derived
from the above).

## Channel creation order

1. On host-a: `configtxgen` with `configtx.yaml` → `genesis.block` + channel tx.
2. On host-a: `osnadmin channel join` (or `peer channel create` from a CLI).
3. On host-a: `peer channel join` for Org1's peer.
4. On host-b: point `peer` at `org2.example.com:7051`, `peer channel join` for
   Org2's peer (gossip pulls blocks from the anchor peer over the internet).
5. Deploy chaincode (see `../docker/NEW_CHAINCODE.md`) on each host; approve
   + commit as usual.
