import { getToken, clearToken } from '../utils/storage';
import { api } from './api';

export async function isLoggedIn(): Promise<boolean> {
  const t = await getToken();
  return !!t;
}

export async function logout() {
  await clearToken();
}

export async function checkAuth(): Promise<boolean> {
  try {
    await api.get('/api/v1/theses');
    return true;
  } catch {
    return false;
  }
}
