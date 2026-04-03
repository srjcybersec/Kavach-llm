import { create } from "zustand";

export type AppEnvironment = "dev" | "staging" | "prod";

type AppState = {
  environment: AppEnvironment;
  accessToken: string | null;
  setEnvironment: (env: AppEnvironment) => void;
  setAccessToken: (token: string | null) => void;
};

export const useAppStore = create<AppState>((set) => ({
  environment: "dev",
  accessToken: null,
  setEnvironment: (environment) => set({ environment }),
  setAccessToken: (accessToken) => set({ accessToken })
}));

