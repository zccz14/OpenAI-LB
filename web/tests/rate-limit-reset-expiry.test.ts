import assert from "node:assert/strict"
import test from "node:test"

import {
  rateLimitResetExpiryStatus,
  rateLimitResetTimestampSeconds,
  sortRateLimitResetCreditsByExpiry,
} from "../src/lib/rate-limit-reset-expiry.ts"

test("parses Unix seconds and ISO-8601 reset-credit timestamps", () => {
  assert.equal(rateLimitResetTimestampSeconds(1_786_029_824), 1_786_029_824)
  assert.equal(
    rateLimitResetTimestampSeconds("2026-08-12T17:43:44.001862Z"),
    1_786_556_624
  )
  assert.equal(rateLimitResetTimestampSeconds("not-a-timestamp"), undefined)
})

test("sorts reset credits by ISO expiry and leaves missing expiry last", () => {
  const credits = sortRateLimitResetCreditsByExpiry([
    { id: "no-expiry", expires_at: null },
    { id: "later", expires_at: "2026-08-13T17:43:44Z" },
    { id: "first", expires_at: "2026-08-12T17:43:44Z" },
  ])

  assert.deepEqual(
    credits.map((credit) => credit.id),
    ["first", "later", "no-expiry"]
  )
})

test("classifies expired and near-expiry reset credits", () => {
  assert.equal(rateLimitResetExpiryStatus(undefined, 1_000), "no-expiry")
  assert.equal(rateLimitResetExpiryStatus(1_000, 1_000), "expired")
  assert.equal(
    rateLimitResetExpiryStatus("1970-01-01T00:16:41Z", 1_000),
    "expires-soon"
  )
  assert.equal(
    rateLimitResetExpiryStatus("1970-01-02T00:16:41Z", 1_000),
    "active"
  )
})
