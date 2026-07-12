import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, ProtectedRoute, useAuth } from './lib/auth';
import { Login } from './pages/Login';
import { Registry } from './pages/Registry';
import { DefenseHall } from './pages/DefenseHall';

const Pending = () => {
  const { roles } = useAuth();
  return (
    <div className="min-h-screen bg-[#0F1219] flex items-center justify-center px-4">
      <div className="text-center max-w-sm">
        <h1 className="font-display text-xl text-slate-100 mb-2">No room assigned</h1>
        <p className="font-body text-sm text-slate-500">
          Your account isn't recognized as registrar or jury. Contact the system administrator to assign a role.
        </p>
        <p className="font-data text-xs text-slate-600 mt-4">
          roles received: {roles.length ? JSON.stringify(roles) : '(none — login response had no roles field)'}
        </p>
      </div>
    </div>
  );
};

const App = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route
            path="/registry"
            element={
              <ProtectedRoute room="registry">
                <Registry />
              </ProtectedRoute>
            }
          />
          <Route
            path="/defense"
            element={
              <ProtectedRoute room="defense">
                <DefenseHall />
              </ProtectedRoute>
            }
          />
          <Route path="/pending" element={<Pending />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
