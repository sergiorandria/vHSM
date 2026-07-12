import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, classifyRoles, roomPath } from '../lib/auth';
import { API_BASE } from '../lib/api';

export const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Access denied');

      login(data.token, data.roles, data.username);
      navigate(roomPath(classifyRoles(data.roles)));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0F1219] flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <svg viewBox="0 0 120 120" className="w-16 h-16 mx-auto mb-4 opacity-90">
            <circle cx="60" cy="60" r="50" fill="none" stroke="var(--gold)" strokeWidth="1.5" />
            <circle cx="60" cy="60" r="41" fill="none" stroke="var(--gold)" strokeWidth="1" opacity="0.5" />
            <text x="60" y="68" textAnchor="middle" fontFamily="Fraunces, serif" fontSize="34" fill="var(--gold-soft)">
              T
            </text>
          </svg>
          <h1 className="font-display text-2xl text-slate-100 tracking-wide">The Thesis Registry</h1>
          <p className="font-body text-sm text-slate-500 mt-1">Sign in to enter your room</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-3 bg-[#171b24] border border-[#2a2f3d] rounded-md p-6">
          {error && (
            <div className="bg-[var(--seal-dark)]/20 border border-[var(--seal)]/40 text-[#e7b3ba] text-sm px-3 py-2 rounded-sm font-body">
              {error}
            </div>
          )}
          <input
            className="hall-input"
            placeholder="Username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            className="hall-input"
            type="password"
            placeholder="Password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[var(--gold)] hover:bg-[var(--gold-soft)] disabled:opacity-40 text-[#1c2333] font-body font-medium text-sm py-2.5 rounded-sm transition-colors tracking-wide"
          >
            {loading ? 'Verifying…' : 'Enter'}
          </button>
        </form>
        <p className="text-center text-xs text-slate-600 mt-4 font-body">
          Registrars are routed to the Registry · Jury members to the Defense Hall
        </p>
      </div>
    </div>
  );
};
