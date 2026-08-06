import assert from "node:assert/strict"
import test from "node:test"

import {
  rateLimitResetExpiryStatus,
  sortRateLimitResetCreditsByExpiry,
} from "../src/lib/rate-limit-reset-expiry.ts"

test("sorts reset credits by their expiry and leaves non-expiring credits last", () => {
  const credits = sortRateLimitResetCreditsByExpiry([
    { id: "no-expiry", expires_at: null },
    { id: "later", expires_at: 200 },
    { id: "first", expires_at: 100 },
  ])

  assert.deepEqual(
    credits.map((credit) => credit.id),
    ["first", "later", "no-expiry"]
  )
})

test("classifies expired and near-expiry reset credits", () => {
  assert.equal(rateLimitResetExpiryStatus(undefined, 1_000), "no-expiry")
  assert.equal(rateLimitResetExpiryStatus(1_000, 1_000), "expired")
  assert.equal(rateLimitResetExpiryStatus(1_001, 1_000), "expires-soon")
  assert.equal(rateLimitResetExpiryStatus(87_401, 1_000), "active")
})
