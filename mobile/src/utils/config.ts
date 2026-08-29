import Constants from 'expo-constants';

type Extra = {
  apiUrl?: string;
};

const extra = (Constants.expoConfig?.extra ?? {}) as Extra;

export const API_URL =
  process.env.EXPO_PUBLIC_API_URL || extra.apiUrl || 'http://localhost:8080';

export const POLL_INTERVAL_MS = 30_000;
export const REQUEST_TIMEOUT_MS = 15_000;
