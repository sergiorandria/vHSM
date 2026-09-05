import * as SecureStore from 'expo-secure-store';

const TOKEN_KEY = 'vhsm_jwt';
const USER_KEY = 'vhsm_user';

export async function saveToken(token: string) {
  await SecureStore.setItemAsync(TOKEN_KEY, token);
}

export async function getToken(): Promise<string | null> {
  return SecureStore.getItemAsync(TOKEN_KEY);
}

export async function clearToken() {
  await SecureStore.deleteItemAsync(TOKEN_KEY);
  await SecureStore.deleteItemAsync(USER_KEY);
}

export async function saveUser(username: string, roles: string[]) {
  await SecureStore.setItemAsync(USER_KEY, JSON.stringify({ username, roles }));
}

export async function getUser(): Promise<{ username: string; roles: string[] } | null> {
  const v = await SecureStore.getItemAsync(USER_KEY);
  return v ? JSON.parse(v) : null;
}
