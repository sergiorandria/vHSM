# Thesis Ledger Tester

A minimal Vite + React + TypeScript + Tailwind test client for the thesis
notarization Go gateway API.

## Setup

```bash
npm install
npm run dev
```

Then open the URL Vite prints (typically http://localhost:5173).

## Configuration

The API base URL is set in `src/lib/api.ts`:

```ts
export const API_BASE = 'http://localhost:8080/api/v1';
```

Change it if your Go gateway runs somewhere else.

## Structure

```
index.html
src/
  main.tsx          entry point
  App.tsx           routes: Login → Registry (superadmin) / Defense Hall (jury)
  index.css         design tokens + Tailwind layers
  lib/
    auth.tsx        auth context, role classification, route guard
    api.ts          fetch wrapper + Thesis type
  components/
    Seal.tsx        wax-seal notarization visual
  pages/
    Login.tsx
    Registry.tsx     superadmin: file a dossier, view the ledger
    DefenseHall.tsx  jury: pick a docket case, submit grade + files, seal it
```

## Role routing

After login, the JWT's `roles` array is classified in `src/lib/auth.tsx`:

- `superadmin` / `admin` / `registrar` → `/registry`
- `jury` / `professor` / `examiner` / `prof` → `/defense`
- anything else → `/pending`

Adjust the alias lists in `classifyRoles()` to match your backend's exact
role strings.
