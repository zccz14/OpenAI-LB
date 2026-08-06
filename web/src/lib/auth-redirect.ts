const LOGIN_CONTEXT_KEY = "openai-lb.auth-mini.login"
const SETUP_DRAFT_KEY = "openai-lb.auth-mini.setup"

type StorageLike = Pick<Storage, "getItem" | "removeItem" | "setItem">

type LoginContext = {
  issuer: string
  state: string
}

export type SetupDraft = {
  issuer: string
  audience: string
}

type RedirectSession = {
  sessionId: string
  accessToken: string
  refreshToken: string
  receivedAt: string
  expiresAt: string
}

export function normalizeAuthMiniIssuer(value: string) {
  const url = new URL(value.trim())
  const local = ["localhost", "127.0.0.1", "::1"].includes(url.hostname)
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.protocol === "http:" && !local)
  ) {
    throw new Error("Auth Mini issuer URL is not valid")
  }
  return url.toString().replace(/\/+$/, "")
}

export function buildAuthMiniLoginUrl(
  issuer: string,
  redirectUri: string,
  state: string,
  audience?: string
) {
  const callback = new URL(redirectUri)
  if (!["http:", "https:"].includes(callback.protocol))
    throw new Error("Auth Mini callback URL is not valid")

  const params = new URLSearchParams({
    redirect_uri: callback.toString(),
    state,
  })
  const callbackAudience = callback.hostname.replace(/^\[|\]$/g, "")
  if (isLoopback(callbackAudience))
    params.set("aud", audience?.trim() || callbackAudience)
  const login = new URL("web/", `${normalizeAuthMiniIssuer(issuer)}/`)
  login.hash = `/login?${params.toString()}`
  return login.toString()
}

export function startAuthMiniLogin(issuer: string, setupDraft?: SetupDraft) {
  const normalizedIssuer = normalizeAuthMiniIssuer(issuer)
  const state = crypto.randomUUID()
  const callback = new URL(window.location.href)
  callback.hash = ""

  sessionStorage.setItem(
    LOGIN_CONTEXT_KEY,
    JSON.stringify({ issuer: normalizedIssuer, state })
  )
  if (setupDraft) {
    sessionStorage.setItem(
      SETUP_DRAFT_KEY,
      JSON.stringify({ ...setupDraft, issuer: normalizedIssuer })
    )
  }
  window.location.assign(
    buildAuthMiniLoginUrl(
      normalizedIssuer,
      callback.toString(),
      state,
      setupDraft?.audience
    )
  )
}

export function consumeAuthMiniCallback() {
  if (!hasAuthMiniCallback(window.location.hash)) return ""

  try {
    adoptAuthMiniCallback(
      window.location.hash,
      localStorage,
      sessionStorage,
      Date.now()
    )
    return ""
  } catch (cause) {
    return cause instanceof Error
      ? cause.message
      : "Auth Mini login callback is invalid"
  } finally {
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${window.location.search}`
    )
  }
}

export function adoptAuthMiniCallback(
  hash: string,
  persistentStorage: StorageLike,
  transientStorage: StorageLike,
  now: number
) {
  const context = readLoginContext(transientStorage)
  try {
    const session = parseAuthMiniCallback(hash, context.state, now)

    // COMPATIBILITY: Auth Mini's public browser SDK has no callback-adoption API.
    // Remove this direct persisted-state write when it exposes one; the callback
    // tests prove safe replacement.
    persistentStorage.setItem(
      authMiniSdkStorageKey(context.issuer),
      JSON.stringify(session)
    )
  } finally {
    transientStorage.removeItem(LOGIN_CONTEXT_KEY)
  }
}

function isLoopback(hostname: string) {
  return ["localhost", "127.0.0.1", "::1"].includes(hostname)
}

export function readAuthMiniSetupDraft(
  storage: StorageLike = sessionStorage
): SetupDraft | null {
  const raw = storage.getItem(SETUP_DRAFT_KEY)
  if (!raw) return null
  try {
    const value = JSON.parse(raw) as Partial<SetupDraft>
    if (typeof value.issuer !== "string" || typeof value.audience !== "string")
      return null
    return {
      issuer: normalizeAuthMiniIssuer(value.issuer),
      audience: value.audience,
    }
  } catch {
    return null
  }
}

export function clearAuthMiniSetupDraft(storage: StorageLike = sessionStorage) {
  storage.removeItem(SETUP_DRAFT_KEY)
}

export function authMiniSdkStorageKey(issuer: string) {
  return `auth-mini.sdk:${normalizeAuthMiniIssuer(issuer)}/`
}

function hasAuthMiniCallback(hash: string) {
  const params = new URLSearchParams(hash.replace(/^#/, ""))
  return ["access_token", "refresh_token", "session_id", "state"].some((key) =>
    params.has(key)
  )
}

function readLoginContext(storage: StorageLike): LoginContext {
  const raw = storage.getItem(LOGIN_CONTEXT_KEY)
  if (!raw)
    throw new Error("Auth Mini login state is missing; start sign-in again")
  try {
    const value = JSON.parse(raw) as Partial<LoginContext>
    if (
      typeof value.issuer !== "string" ||
      typeof value.state !== "string" ||
      !value.state
    )
      throw new Error()
    return { issuer: normalizeAuthMiniIssuer(value.issuer), state: value.state }
  } catch {
    throw new Error("Auth Mini login state is invalid; start sign-in again")
  }
}

function parseAuthMiniCallback(
  hash: string,
  expectedState: string,
  now: number
): RedirectSession {
  const params = new URLSearchParams(hash.replace(/^#/, ""))
  if (params.get("state") !== expectedState)
    throw new Error("Auth Mini login state does not match")

  const accessToken = params.get("access_token")
  const refreshToken = params.get("refresh_token")
  const sessionId = params.get("session_id")
  const expiresIn = Number(params.get("expires_in"))
  if (
    !accessToken ||
    !refreshToken ||
    !sessionId ||
    params.get("token_type") !== "Bearer" ||
    !Number.isInteger(expiresIn) ||
    expiresIn <= 0
  ) {
    throw new Error("Auth Mini login callback is incomplete")
  }

  const receivedAt = new Date(now).toISOString()
  const suppliedExpiry = params.get("expires_at")
  const expiresAtMs = suppliedExpiry
    ? Date.parse(suppliedExpiry)
    : now + expiresIn * 1000
  if (!Number.isFinite(expiresAtMs))
    throw new Error("Auth Mini login callback expiry is invalid")

  return {
    sessionId,
    accessToken,
    refreshToken,
    receivedAt,
    expiresAt: new Date(expiresAtMs).toISOString(),
  }
}
