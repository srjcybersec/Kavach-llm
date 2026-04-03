import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiResponse<T> = { success: boolean; data: T; error?: string; details?: string };

type AuthUser = { id: string; email: string; role: string };

type LoginResponse = {
  user: AuthUser;
  accessToken: string;
  refreshToken: string;
};

type AuthBody = {
  email: string;
  password: string;
};

const DEMO_EMAIL = "judge@kavach.local";
const DEMO_PASSWORD = "JudgeKavach123!";

async function postJson<T>(path: string, body: unknown): Promise<ApiResponse<T>> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });

  const json = (await res.json()) as ApiResponse<T>;
  return json;
}

export async function ensureDemoAuth(): Promise<string> {
  const { accessToken } = useAppStore.getState();
  if (accessToken) return accessToken;

  // Try login first (idempotent for repeat runs).
  const login = await postJson<LoginResponse>("/auth/login", { email: DEMO_EMAIL, password: DEMO_PASSWORD } satisfies AuthBody);
  if (login.success) {
    useAppStore.getState().setAccessToken(login.data.accessToken);
    return login.data.accessToken;
  }

  // Fallback to register.
  const register = await postJson<unknown>("/auth/register", { email: DEMO_EMAIL, password: DEMO_PASSWORD } satisfies AuthBody);
  if (!register.success) {
    const base = register.error ?? "Demo auth failed";
    const hint = register.details ? ` ${register.details}` : "";
    throw new Error(`${base}.${hint}`);
  }

  const login2 = await postJson<LoginResponse>("/auth/login", { email: DEMO_EMAIL, password: DEMO_PASSWORD } satisfies AuthBody);
  if (!login2.success) {
    const base = login2.error ?? "Demo login failed";
    const hint = login2.details ? ` ${login2.details}` : "";
    throw new Error(`${base}.${hint}`);
  }

  useAppStore.getState().setAccessToken(login2.data.accessToken);
  return login2.data.accessToken;
}

