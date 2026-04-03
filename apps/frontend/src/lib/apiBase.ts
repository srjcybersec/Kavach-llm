/** API origin without `/api/v1` (for Socket.IO, health checks). */
export function getApiOrigin(): string {
  const apiV1 = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";
  return apiV1.replace(/\/api\/v1\/?$/, "");
}

export function getApiV1Base(): string {
  return import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";
}
