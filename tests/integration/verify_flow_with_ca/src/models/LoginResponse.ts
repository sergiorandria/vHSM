export interface LoginResponse {
    token: string;
    username: string;
    roles: string[];
    expires_in: number; // seconds
}
