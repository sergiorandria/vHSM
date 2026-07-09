import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';

const API_BASE = 'http://localhost:8080/api/v1';

// --- Auth Context ---
interface AuthContextType {
  token: string | null;
  roles: string[];
  login: (token: string, roles: string[]) => void;
  logout: () => void;
}
const AuthContext = createContext<AuthContextType>(null!);

const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [roles, setRoles] = useState<string[]>(JSON.parse(localStorage.getItem('roles') || '[]'));

  const login = (newToken: string, newRoles: string[]) => {
    setToken(newToken);
    setRoles(newRoles);
    localStorage.setItem('token', newToken);
    localStorage.setItem('roles', JSON.stringify(newRoles));
  };

  const logout = () => {
    setToken(null);
    setRoles([]);
    localStorage.removeItem('token');
    localStorage.removeItem('roles');
  };

  return <AuthContext.Provider value={{ token, roles, login, logout }}>{children}</AuthContext.Provider>;
};

// --- API Helper ---
const useApi = () => {
  const { token, logout } = useContext(AuthContext);
  
  const fetchApi = async (endpoint: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);
    
    const response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    if (response.status === 401) {
      logout();
      throw new Error('Unauthorized');
    }
    return response;
  };
  return fetchApi;
};

// --- Components ---

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login failed');
      
      login(data.token, data.roles);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="flex items-center justify-center h-[80vh]">
      <div className="glass-panel p-8 w-full max-w-md">
        <h2 className="text-2xl font-semibold mb-6 text-center tracking-wide text-white">System Access</h2>
        {error && <div className="bg-red-500/20 border border-red-500/50 text-red-200 p-3 rounded mb-4 text-sm">{error}</div>}
        <form onSubmit={handleLogin} className="space-y-4">
          <input className="glass-input" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
          <input className="glass-input" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
          <button className="glass-button mt-4" type="submit">Authenticate</button>
        </form>
      </div>
    </div>
  );
};

const SuperAdminPanel = () => {
  const api = useApi();
  const [status, setStatus] = useState('');

  // Pre-filled with contextual placeholder data
  const [formData, setFormData] = useState({
    thesisId: `TH-${Date.now()}`,
    studentId: 'STD-1002',
    student: {
      fullName: 'S. Randriamihoatra',
      email: 'student@example.mg',
      enrollmentYear: 2024,
      program: 'Computer Science',
      department: 'Systems Engineering'
    },
    administrative: {
      institution: "Université d'Antananarivo",
      faculty: "Faculté des Sciences",
      academicYear: "2025-2026",
      supervisorName: "Dr. T. Razafitrimo",
      defenseDate: new Date().toISOString(),
      registrationDate: new Date().toISOString()
    },
    metadata: {
      title: "Kernel Rootkit Detector: Syscall Scanner in Rust",
      language: "fr",
      submittedAt: new Date().toISOString()
    }
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('Creating...');
    try {
      const res = await api('/theses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStatus(`Success: Thesis ${data.thesisId} recorded on ledger.`);
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
    }
  };

  return (
    <div className="glass-panel p-6 max-w-2xl mx-auto mb-8">
      <h3 className="text-xl font-medium mb-4 border-b border-slate-700 pb-2">Pre-Defense Registration (SuperAdmin)</h3>
      <form onSubmit={handleSubmit} className="space-y-4 text-sm">
        <div className="grid grid-cols-2 gap-4">
          <input className="glass-input" value={formData.thesisId} onChange={e => setFormData({...formData, thesisId: e.target.value})} placeholder="Thesis ID" />
          <input className="glass-input" value={formData.student.fullName} onChange={e => setFormData({...formData, student: {...formData.student, fullName: e.target.value}})} placeholder="Student Name" />
        </div>
        <input className="glass-input" value={formData.metadata.title} onChange={e => setFormData({...formData, metadata: {...formData.metadata, title: e.target.value}})} placeholder="Thesis Title" />
        <div className="grid grid-cols-2 gap-4">
          <input className="glass-input" value={formData.administrative.institution} onChange={e => setFormData({...formData, administrative: {...formData.administrative, institution: e.target.value}})} placeholder="Institution" />
          <input className="glass-input" value={formData.administrative.supervisorName} onChange={e => setFormData({...formData, administrative: {...formData.administrative, supervisorName: e.target.value}})} placeholder="Supervisor" />
        </div>
        <button className="glass-button" type="submit">Commit Draft to Ledger</button>
      </form>
      {status && <div className="mt-4 text-emerald-400 bg-emerald-900/20 p-3 rounded border border-emerald-800/50">{status}</div>}
    </div>
  );
};

const JuryPanel = () => {
  const api = useApi();
  const [thesisId, setThesisId] = useState('');
  const [grade, setGrade] = useState('');
  const [pvFile, setPvFile] = useState<File | null>(null);
  const [docFile, setDocFile] = useState<File | null>(null);
  const [status, setStatus] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pvFile || !docFile) return setStatus('Both files required.');
    
    setStatus('Encrypting and submitting to HSM/MinIO...');
    const formData = new FormData();
    formData.append('ThesisId', thesisId);
    formData.append('Grade', grade);
    formData.append('Pv', pvFile);
    formData.append('Document', docFile);

    try {
      const res = await api('/submissions', {
        method: 'POST',
        // Note: Do not set Content-Type; browser automatically sets multipart boundary
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStatus(`Defense recorded! PV Hash: ${data.pv.hash.substring(0, 16)}...`);
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
    }
  };

  return (
    <div className="glass-panel p-6 max-w-2xl mx-auto mb-8">
      <h3 className="text-xl font-medium mb-4 border-b border-slate-700 pb-2">Defense Submission (Jury)</h3>
      <form onSubmit={handleSubmit} className="space-y-4 text-sm">
        <div className="grid grid-cols-2 gap-4">
          <input className="glass-input" placeholder="Target Thesis ID" value={thesisId} onChange={e => setThesisId(e.target.value)} required />
          <input className="glass-input" placeholder="Final Grade (e.g. 18/20)" value={grade} onChange={e => setGrade(e.target.value)} required />
        </div>
        <div>
          <label className="block text-slate-400 mb-1">Procès-Verbal (PV)</label>
          <input type="file" className="glass-input cursor-pointer" onChange={e => setPvFile(e.target.files?.[0] || null)} required />
        </div>
        <div>
          <label className="block text-slate-400 mb-1">Final Thesis PDF</label>
          <input type="file" className="glass-input cursor-pointer" onChange={e => setDocFile(e.target.files?.[0] || null)} required />
        </div>
        <button className="glass-button !bg-emerald-600/80 hover:!bg-emerald-500/80 !border-emerald-500/30" type="submit">Submit & Notarize</button>
      </form>
      {status && <div className="mt-4 text-blue-400 bg-blue-900/20 p-3 rounded border border-blue-800/50">{status}</div>}
    </div>
  );
};

const ThesisList = () => {
  const api = useApi();
  const [theses, setTheses] = useState<any[]>([]);

  useEffect(() => {
    api('/theses').then(r => r.json()).then(data => setTheses(data || [])).catch(console.error);
  }, []);

  return (
    <div className="glass-panel p-6 max-w-4xl mx-auto">
      <div className="flex justify-between items-center mb-4 border-b border-slate-700 pb-2">
        <h3 className="text-xl font-medium">Ledger State</h3>
        <button className="text-sm bg-slate-700/50 px-3 py-1 rounded hover:bg-slate-600/50 transition" onClick={() => api('/theses').then(r => r.json()).then(data => setTheses(data || []))}>Refresh</button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-slate-400 bg-slate-800/50">
            <tr>
              <th className="px-4 py-2 rounded-tl-lg">ID</th>
              <th className="px-4 py-2">Student</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Grade</th>
              <th className="px-4 py-2 rounded-tr-lg">Doc Hash (Proof)</th>
            </tr>
          </thead>
          <tbody>
            {theses.map((t, i) => (
              <tr key={i} className="border-b border-slate-700/50 hover:bg-slate-700/20 transition-colors">
                <td className="px-4 py-3 font-mono">{t.thesisId}</td>
                <td className="px-4 py-3">{t.student?.fullName}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs ${t.status === 'DRAFT' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'}`}>
                    {t.status}
                  </span>
                </td>
                <td className="px-4 py-3">{t.grade || '-'}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{t.hashDocument ? `${t.hashDocument.substring(0, 12)}...` : 'Pending'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {theses.length === 0 && <div className="text-center py-6 text-slate-500">No records found on ledger.</div>}
      </div>
    </div>
  );
};

const Dashboard = () => {
  const { logout, roles } = useContext(AuthContext);
  const navigate = useNavigate();

  return (
    <div className="p-6">
      <div className="flex justify-between items-center max-w-4xl mx-auto mb-8 bg-slate-800/30 p-4 rounded-xl border border-slate-700/50 backdrop-blur-sm">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Fabric Gateway App</h1>
          <p className="text-slate-400 text-sm mt-1">Active Roles: {roles.join(', ') || 'Unknown'}</p>
        </div>
        <button onClick={() => { logout(); navigate('/'); }} className="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 px-4 py-2 rounded-lg transition-all">
          Disconnect
        </button>
      </div>

      {/* Basic Role Routing - adjust conditional logic based on your exact JWT role names */}
      <SuperAdminPanel />
      <JuryPanel />
      <ThesisList />
    </div>
  );
};

const App = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
