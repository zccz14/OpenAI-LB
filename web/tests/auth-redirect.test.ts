import assert from "node:assert/strict"
import test from "node:test"

import {
  adoptAuthMiniCallback,
  authMiniSdkStorageKey,
  buildAuthMiniLoginUrl,
  normalizeAuthMiniIssuer,
  readAuthMiniSetupDraft,
} from "../src/lib/auth-redirect.ts"

class MemoryStorage {
  readonly values = new Map<string, string>()

  getItem(key: string) {
    return this.values.get(key) ?? null
  }
  removeItem(key: string) {
    this.values.delete(key)
  }
  setItem(key: string, value: string) {
    this.values.set(key, value)
  }
}

test("builds the hosted Auth Mini login URL", () => {
  assert.equal(
    buildAuthMiniLoginUrl(
      "https://auth.ntnl.io/",
      "https://openai.ntnl.io/",
      "state-1"
    ),
    "https://auth.ntnl.io/web/#/login?redirect_uri=https%3A%2F%2Fopenai.ntnl.io%2F&state=state-1"
  )
})

test("sets the required audience for a loopback callback", () => {
  assert.equal(
    buildAuthMiniLoginUrl(
      "http://127.0.0.1:7777",
      "http://127.0.0.1:8080/",
      "state-1"
    ),
    "http://127.0.0.1:7777/web/#/login?redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2F&state=state-1&aud=127.0.0.1"
  )
})

test("accepts HTTPS and localhost issuers only", () => {
  assert.equal(
    normalizeAuthMiniIssuer("https://auth.ntnl.io/"),
    "https://auth.ntnl.io"
  )
  assert.equal(
    normalizeAuthMiniIssuer("http://127.0.0.1:7777/"),
    "http://127.0.0.1:7777"
  )
  assert.throws(() => normalizeAuthMiniIssuer("http://auth.example.com"))
  assert.throws(() => normalizeAuthMiniIssuer("https://user@auth.example.com"))
})

test("validates state and adopts callback tokens into the pinned SDK storage shape", () => {
  const persistent = new MemoryStorage()
  const transient = new MemoryStorage()
  transient.setItem(
    "openai-lb.auth-mini.login",
    JSON.stringify({ issuer: "https://auth.ntnl.io", state: "state-1" })
  )

  adoptAuthMiniCallback(
    "#access_token=jwt&token_type=Bearer&session_id=session-1&refresh_token=refresh&expires_in=900&state=state-1",
    persistent,
    transient,
    Date.parse("2026-07-16T08:00:00.000Z")
  )

  assert.deepEqual(
    JSON.parse(
      persistent.getItem(authMiniSdkStorageKey("https://auth.ntnl.io")) ??
        "null"
    ),
    {
      sessionId: "session-1",
      accessToken: "jwt",
      refreshToken: "refresh",
      receivedAt: "2026-07-16T08:00:00.000Z",
      expiresAt: "2026-07-16T08:15:00.000Z",
    }
  )
  assert.equal(transient.getItem("openai-lb.auth-mini.login"), null)
})

test("rejects a mismatched callback state and consumes the one-time context", () => {
  const persistent = new MemoryStorage()
  const transient = new MemoryStorage()
  transient.setItem(
    "openai-lb.auth-mini.login",
    JSON.stringify({ issuer: "https://auth.ntnl.io", state: "expected" })
  )

  assert.throws(
    () =>
      adoptAuthMiniCallback(
        "#access_token=jwt&token_type=Bearer&session_id=session-1&refresh_token=refresh&expires_in=900&state=wrong",
        persistent,
        transient,
        Date.now()
      ),
    /does not match/
  )
  assert.equal(persistent.values.size, 0)
  assert.equal(transient.getItem("openai-lb.auth-mini.login"), null)
})

test("restores the setup draft after the hosted login round trip", () => {
  const storage = new MemoryStorage()
  storage.setItem(
    "openai-lb.auth-mini.setup",
    JSON.stringify({ issuer: "https://auth.ntnl.io/", audience: "openai-lb" })
  )
  assert.deepEqual(readAuthMiniSetupDraft(storage), {
    issuer: "https://auth.ntnl.io",
    audience: "openai-lb",
  })
})
