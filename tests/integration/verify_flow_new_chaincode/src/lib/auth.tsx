import React, { createContext, useContext, useState } from 'react';
import { Navigate } from 'react-router-dom';

export interface AuthContextType {
  token: string | null;
  roles: string[];
  // The authenticated LDAP username. This is what the chaincode compares
  // against Administrative.JuryMembers entries (see chaincode.go's
  // isJuryMember) and what the API takes jurorId from server-side — so the
  // frontend needs it too, to know which docket items belong to "me".
  username: string | null;
  login: (token: string, roles: string[], username: string) => void;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextType>(null!);
export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [roles, setRoles] = useState<string[]>(JSON.parse(localStorage.getItem('roles') || '[]'));
  const [username, setUsername] = useState<string | null>(localStorage.getItem('username'));

  const login = (newToken: string, newRoles: string[], newUsername: string) => {
    setToken(newToken);
    setRoles(newRoles);
    setUsername(newUsername);
    localStorage.setItem('token', newToken);
    localStorage.setItem('roles', JSON.stringify(newRoles));
    localStorage.setItem('username', newUsername);
  };

  const logout = () => {
    setToken(null);
    setRoles([]);
    setUsername(null);
    localStorage.removeItem('token');
    localStorage.removeItem('roles');
    localStorage.removeItem('username');
  };

  return <AuthContext.Provider value={{ token, roles, username, login, logout }}>{children}</AuthContext.Provider>;
};

// --- Role classification ---
// The registrar files paperwork before the fact; the jury judges and seals
// after the fact. These are genuinely different jobs, so a person is routed
// to exactly one room based on their roles claim from the login response.
export type RoomKey = 'registry' | 'defense' | 'unknown';

// These must stay in sync with electronic_signature/rest_api/internal/roles.go
// on the Go API — that file is the actual source of truth (it's what
// LDAP group CNs get mapped to, and what requirePermission checks against).
// As of the current backend:
//   RoleAdmin     = "admin"
//   RoleProfessor = "professeurs"   (French — not "professor"/"prof")
//   RoleStudent   = "etudiants"     (no room in this app yet — falls through to /pending)
const SUPERADMIN_ALIASES = ['admin', 'superadmin', 'registrar'];
const JURY_ALIASES = ['professeurs', 'jury', 'professor', 'examiner'];

export function classifyRoles(roles: string[]): RoomKey {
  const lower = roles.map((r) => r.toLowerCase());
  // Exact match against the backend's role strings, with a few generic
  // fallbacks kept in case the backend config changes. Substring matching
  // was dropped in favor of exact matching now that the real values are
  // known — it's less likely to misclassify a role that happens to share
  // a fragment with another (e.g. "administrateurs" vs "admin").
  if (lower.some((r) => SUPERADMIN_ALIASES.includes(r))) return 'registry';
  if (lower.some((r) => JURY_ALIASES.includes(r))) return 'defense';
  return 'unknown';
}

export function roomPath(room: RoomKey): string {
  if (room === 'registry') return '/registry';
  if (room === 'defense') return '/defense';
  return '/pending';
}

// Gate a route to a specific room. Sends people to their own room rather
// than a bare "forbidden" wall if they land on the wrong one.
export const ProtectedRoute = ({
  room,
  children,
}: {
  room: 'registry' | 'defense';
  children: React.ReactNode;
}) => {
  const { token, roles } = useAuth();
  if (!token) return <Navigate to="/" replace />;

  const actual = classifyRoles(roles);
  if (actual !== room) return <Navigate to={roomPath(actual)} replace />;

  return <>{children}</>;
};
