# Real Fabric network — multi-host deployment (local + internet)

This folder holds **configuration templates** for running vHSM's Hyperledger
Fabric ledger across **separate machines** — for example:

- the **orderer** and **Org1** run on a local machine / LAN, while
- **Org2** runs on an internet-reachable VM,

as opposed to the single-host, all-in-one Docker stack in
[`../docker`](../docker) (where every container lives on one host and talks
over the `fabric` Docker network).

> These are **templates with placeholders** (`<...>` / `CHANGE_ME`). Fill in
> your real hostnames, IPs, DNS and certificate paths before use. They are a
> starting point, not a turn-key deployment.

## What is different from `../docker`

| Concern | `../docker` (single host) | `real-network` (multi-host) |
|---|---|---|
| Node placement | All peers/orderer in one `docker-compose.yaml` | One compose/unit **per host** (see `docker-compose.org1.yaml`) |
| Addressing | Container names (`peer0.misa.university.com:7051`) | **Public DNS/IP** of each host (gossip external endpoint) |
| TLS | SANs = container names / `localhost` | SANs must include the **public hostname** of each host |
| Crypto | Generated under `./organizations` on one host | Each org generates its own crypto on **its** host; only public TLS CAs are exchanged |
| Gossip | `CORE_PEER_GOSSIP_EXTERNALENDPOINT` = container addr | Set to the host's **internet/LAN address** so cross-host gossip works |
| Firewall | None (single Docker network) | Open `7050/7051/7052/7053` (+ operations `7053/17054/...`) per host |
| Clients (vHSM) | Endpoint = `localhost:7051` | Endpoint = the **internet** address of the orderer/peer (`VHSM_LEDGER_ENDPOINT`) |

## Suggested workflow

1. **Generate crypto per org.** Reuse the PKI generator logic from
   `../docker/generate-network.sh` (Fabric-CA + PostgreSQL + OpenLDAP per org),
   but run it **on each org's own host** so private keys never leave the machine.
   Exchange only the `tls/ca.crt` (public TLS root) between orgs.
2. **Author the channel config.** Edit `configtx.yaml` (consenter addresses =
   the orderer's public host). Generate the genesis block + channel tx with
   `configtxgen` on the orderer host.
3. **Bring up each host.** Deploy `docker-compose.org1.yaml` (and its org2
   variant) on each machine, binding crypto from a host directory such as
   `/etc/vhsmd/organizations`. See `.env.example` for the variables.
4. **Create/join the channel** with `osnadmin` + `peer channel join` (same
   commands as `../docker`, but addresses are now public hosts).
5. **Deploy the chaincode.** Follow `../docker/NEW_CHAINCODE.md` /
   `../docker/REBUILD_IMG.md`; the chaincode servers run on each peer host and
   are reached over TLS by their public address.
6. **Point vHSM at the network.** Set `VHSM_LEDGER_ENDPOINT`,
   `VHSM_LEDGER_CERT`, `VHSM_LEDGER_KEY`, `VHSM_LEDGER_CA`,
   `VHSM_LEDGER_SERVER_NAME`, `VHSM_LEDGER_MSP_ID` to the **internet-reachable**
   gateway endpoint and the org's TLS identity (see `connection-org1.json`
   for the equivalent client-side profile).

## Files

- `configtx.yaml` — channel/orderer/organization definitions (consenters use
  public hostnames). Feed to `configtxgen`.
- `docker-compose.org1.yaml` — template to run **one org's** peer stack on a
  real host (per-host deployment).
- `connection-org1.json` — Hyperledger Gateway connection profile template for
  a client (vHSM C++ `LedgerClient` / Go REST API) pointing at the public
  endpoints.
- `.env.example` — variables referenced by `docker-compose.org1.yaml`.
- `topology.md` — a concrete local-machine + internet-machine example.

See also: `../docker/README.md` (single-host how-to) and
`../../docs/FABRIC_CHAINCODE.md` (chaincode + client wiring).
