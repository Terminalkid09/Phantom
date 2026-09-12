/// <reference types="vite/client" />

interface PhantomApi {
  getApiUrl(): Promise<string>
  onApiStatus(cb: (s: { state: string; detail?: string; code?: number | null }) => void): void
  request(method: string, endpoint: string, body?: unknown): Promise<{ status: number; data: unknown }>
  get(endpoint: string): Promise<{ status: number; data: unknown }>
  post(endpoint: string, body?: unknown): Promise<{ status: number; data: unknown }>
  put(endpoint: string, body?: unknown): Promise<{ status: number; data: unknown }>
  delete(endpoint: string): Promise<{ status: number; data: unknown }>
  getVersion(): Promise<string>
  saveArtifact(payload: { name: string; data: string }, dir?: string): Promise<{ saved: boolean; path?: string; error?: string }>
  saveArtifactAuto(payload: { name: string; data: string }, dir?: string): Promise<{ saved: boolean; path?: string; error?: string }>
}

interface Window {
  phantom: PhantomApi
}