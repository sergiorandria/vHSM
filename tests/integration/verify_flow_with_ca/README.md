# Thesis Submission — Frontend

A small Vite + TypeScript app that talks to the Go REST API (`/api/v1/login`,
`/api/v1/theses`, `/api/v1/submissions`).

## What was added to your existing files

Your `thesis.ts`, `submissions.ts`, `main.ts`, and `index.html` covered the
UI and the two data-fetching calls, but a few pieces were missing to make
this a runnable app against your Go backend:

- **`src/api/auth.ts`** — calls `POST /api/v1/login`, stores the JWT +
  username + roles in `sessionStorage`, and exposes `authHeader()`. Your
  Go middleware (`authRequired` / `requirePermission`) rejects any request
  without a valid `Authorization: Bearer <token>` header, but the uploaded
  `thesis.ts`/`submissions.ts` never sent one.
- **`src/models/`** — `Thesis`, `SubmissionRequest`, `SubmissionResponse`,
  and `LoginResponse` types, which were imported but not included in the
  upload.
- **Login gate in `index.html` / `main.ts`** — a sign-in card shown until
  there's a valid session, a logout button, and 401 handling that drops
  the user back to the login screen if the token expires mid-session.
- **`package.json` / `tsconfig.json` / `vite.config.ts`** — project
  scaffolding so `npm run dev` actually serves the app (your `index.html`
  already assumed a Vite setup via `<script type="module" src="/src/main.ts">`).
- Renamed `theses.ts` → `thesis.ts` to match the import path used in
  `main.ts` (`./api/thesis`).

## Run it

```bash
npm install
npm run dev
```

This serves the app at http://localhost:5173. It expects the Go API
running at http://localhost:8080 (hardcoded as `API_URL` in each
`src/api/*.ts` file — change those if your backend runs elsewhere).

## Build

```bash
npm run build
```

Output goes to `dist/`.

## Notes / things worth double-checking against your backend

- **CORS**: your Go server's middleware echoes back whatever `Origin`
  header it receives and sets `Access-Control-Allow-Credentials: true`.
  That's permissive — fine for local dev, but worth tightening (an
  explicit allow-list) before this goes anywhere public.
- **Token storage**: using `sessionStorage` rather than `localStorage` so
  the JWT doesn't persist after the tab closes. It's still readable by any
  script on the page (XSS risk), which is inherent to bearer tokens kept
  in the browser rather than an httpOnly cookie — worth knowing if this
  moves past a school project.
- **Session expiry**: the app decodes `expires_in` from the login response
  into a client-side expiry timestamp. It does not refresh tokens — once
  it expires, the user has to log in again.
