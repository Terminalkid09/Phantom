import { useSyncExternalStore } from 'react'

import { getSnapshot, subscribe } from '@/lib/apiActivity'

export type { ApiActivity } from '@/lib/apiActivity'
export {
  beginApiActivity,
  isBackgroundRequest,
  runAsBackgroundRequest,
  _resetApiActivity,
} from '@/lib/apiActivity'

/** Subscribe the app shell to the global API activity store. */
export function useApiActivity() {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}
