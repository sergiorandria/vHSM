# Integration test: verify_flow

Instructions to run the local backend and test the TypeScript submission helper.

Prerequisites:
- Go 1.18+ installed
- SoftHSM installed and configured, or set `HSM_PIN` env var to a valid value for testing
- Node.js (optional) to run the TS helper

Run backend:

```bash
export HSM_PIN=1234              # or your PIN
cd rest_api
go run .
```

The server listens on `:8080` and exposes `POST /api/v1/submissions`.

Test with curl:

```bash
curl -v -X POST http://localhost:8080/api/v1/submissions \
  -H 'Content-Type: application/json' \
  -d '{"thesisId":"t1","grade":95,"metadata":{"foo":"bar"}}'
```

Use the TypeScript helper (node):

```bash
# from tests/integration/verify_flow
node -e "(async ()=>{const {submit}=require('./src/api/submissions'); const payload={thesisId:'t1',grade:95,metadata:{foo:'bar'}}; try{const r=await submit(payload); console.log('OK',r);}catch(e){console.error(e);} })()"
```
