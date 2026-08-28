# vHSM Audit UI

Read-only web interface for vHSM. It lets students, professors and auditors:

- **Verify a signature** — look up a `recordId` anchored on the Fabric
  `signature_ledger` chaincode and see its block-inclusion proof
  (`tx_id`, `block_number`, `key_fingerprint`, `submitter`, `payload_digest`,
  `signature_b64`, `created_at`).
- **Thesis** — inspect a thesis record's current state and its transaction
  history timeline (reusing the existing `GET /api/v1/theses/:id` and
  `GET /api/v1/theses/:id/history` endpoints).

The app is **read-only**: it only issues `GET` requests and never mutates the
ledger.

## Build

```bash
cd web
npm install
npm run build      # produces dist/ which the Go API serves at "/"
```

`npm run build` writes to `web/dist`. The Go REST API (`rest_api/cmd/api`)
serves that directory and falls back to `index.html` for client-side routing.
`go build ./...` does **not** require `web/dist` to exist — if the directory is
missing the API simply returns 404 for UI paths.

## Local development

```bash
npm run dev         # vite dev server, proxies /api to http://localhost:8080
```

Vite is configured (`vite.config.js`) to proxy `/api` to the running Go API on
`:8080`, so the browser can call the API without CORS friction during dev.

## Authentication

All API endpoints require a valid JWT bearer token. Log in via
`POST /api/v1/login` (username/password against LDAP) to obtain one, then paste
the token into the **JWT** box at the top of the UI. The token is stored in
`localStorage` under `vhsm_jwt` and sent as `Authorization: Bearer <token>` on
every request.

If you do not have LDAP credentials, any valid token issued by the API works for
development — the UI only needs the `ReadThesis` permission to use either page.

## Serving from the Go API

Once `web/dist` exists, start the Go API (default port `8080`) and open
`http://localhost:8080/` — the SPA is served from there. Unknown non-`/api`
paths fall back to `index.html` so the in-app navigation works on refresh.

## Notes

- `GET /api/v1/audit/tail` is a placeholder that returns `501` (the audit tail
  HMAC is maintained by the C++ `vhsmd` daemon, which owns the local audit log;
  this Go process cannot compute it).
- The signature proof reads from the `signature_ledger` chaincode, whose name and
  channel are configurable via `SIGNATURE_CHAINCODE_NAME` / `SIGNATURE_CHANNEL_NAME`
  (defaults `signature_ledger` / `signaturechannel`).
