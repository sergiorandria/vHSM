import axios from 'axios';
import { API_URL, REQUEST_TIMEOUT_MS } from '../utils/config';
import { getToken } from '../utils/storage';

export const api = axios.create({
  baseURL: API_URL,
  timeout: REQUEST_TIMEOUT_MS,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use(async (config) => {
  const token = await getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      // Let caller handle logout
    }
    return Promise.reject(err);
  }
);

export async function login(username: string, password: string) {
  const { data } = await api.post('/api/v1/login', { username, password });
  return data as { token: string; username: string; roles: string[]; expires_in: number };
}

export async function fetchTheses() {
  const { data } = await api.get('/api/v1/theses');
  return data;
}

export async function fetchThesis(thesisId: string) {
  const { data } = await api.get(`/api/v1/theses/${thesisId}`);
  return data;
}

export async function fetchJuryStatus(thesisId: string) {
  const { data } = await api.get(`/api/v1/theses/${thesisId}/jury-status`);
  return data;
}

export async function fetchHistory(thesisId: string) {
  const { data } = await api.get(`/api/v1/theses/${thesisId}/history`);
  return data;
}

export async function fetchProof(recordId: string) {
  const { data } = await api.get(`/api/v1/proof/${recordId}`);
  return data;
}

export async function fetchVerify(recordId: string) {
  const { data } = await api.get(`/api/v1/verify/${recordId}`);
  return data as {
    record_id: string;
    record_found: boolean;
    valid: boolean;
    integrity_hmac_ok: boolean;
    ledger_cross_check_ok: boolean;
    ledger_status: string;
    ledger_tx_id?: string;
    ledger_block_num?: number;
    error_detail?: string;
  };
}

export async function fetchAuditTail() {
  const { data } = await api.get('/api/v1/audit/tail');
  return data;
}

export async function registerDevice(fcmToken: string, platform: string) {
  const { data } = await api.post('/api/v1/mobile/devices', {
    fcm_token: fcmToken,
    platform,
  });
  return data;
}
