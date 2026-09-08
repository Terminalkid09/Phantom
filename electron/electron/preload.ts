import { contextBridge, ipcRenderer } from 'electron'

export interface ApiResponse {
  status: number
  data: unknown
}

const api = {
  /** Fetch the base URL of the local Python API server */
  getApiUrl: (): Promise<string> => ipcRenderer.invoke('get-api-url'),

  /** Subscribe to backend lifecycle events (error / exit) from main */
  onApiStatus: (cb: (s: { state: string; detail?: string; code?: number | null }) => void): void => {
    ipcRenderer.on('api-status', (_e, status) => cb(status))
  },

  /** Generic request to the Python API */
  request: (method: string, endpoint: string, body?: unknown): Promise<ApiResponse> =>
    ipcRenderer.invoke('api-request', method, endpoint, body),

  // Convenience methods
  get: (endpoint: string) => ipcRenderer.invoke('api-request', 'GET', endpoint),
  post: (endpoint: string, body?: unknown) =>
    ipcRenderer.invoke('api-request', 'POST', endpoint, body),
  put: (endpoint: string, body?: unknown) =>
    ipcRenderer.invoke('api-request', 'PUT', endpoint, body),
  delete: (endpoint: string) => ipcRenderer.invoke('api-request', 'DELETE', endpoint),

  getVersion: (): Promise<string> => ipcRenderer.invoke('get-version')
}

contextBridge.exposeInMainWorld('phantom', api)