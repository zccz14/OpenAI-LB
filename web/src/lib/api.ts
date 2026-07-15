import type { createBrowserSdk } from "auth-mini/sdk/browser"

export type AuthSdk = ReturnType<typeof createBrowserSdk>

async function accessToken(sdk: AuthSdk, forceRefresh = false) {
  const current = sdk.session.getState()
  if (!forceRefresh && current.accessToken) return current.accessToken
  const refreshed = await sdk.session.refresh()
  if (!refreshed.accessToken) throw new Error("Authentication session is unavailable")
  return refreshed.accessToken
}

export async function api<T>(sdk: AuthSdk, path: string, init?: RequestInit): Promise<T> {
  async function request(forceRefresh: boolean) {
    return fetch(path, {
      ...init,
      headers: {
        accept: "application/json",
        ...(init?.body ? { "content-type": "application/json" } : {}),
        ...init?.headers,
        authorization: `Bearer ${await accessToken(sdk, forceRefresh)}`,
      },
    })
  }

  let response = await request(false)
  if (response.status === 401 && sdk.session.getState().refreshToken) response = await request(true)
  const payload = (await response.json()) as T | { error?: { message?: string } }
  if (!response.ok) {
    const message = "error" in (payload as object) ? (payload as { error?: { message?: string } }).error?.message : undefined
    throw new Error(message || `Request failed (${response.status})`)
  }
  return payload as T
}
