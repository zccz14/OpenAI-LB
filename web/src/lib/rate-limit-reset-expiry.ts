export type RateLimitResetCreditExpiry = {
  expires_at?: number | null
}

export type RateLimitResetExpiryStatus =
  "no-expiry" | "expired" | "expires-soon" | "active"

export function sortRateLimitResetCreditsByExpiry<
  T extends RateLimitResetCreditExpiry,
>(credits: readonly T[]) {
  return [...credits].sort(
    (left, right) =>
      (left.expires_at ?? Number.POSITIVE_INFINITY) -
      (right.expires_at ?? Number.POSITIVE_INFINITY)
  )
}

export function rateLimitResetExpiryStatus(
  expiresAt: number | null | undefined,
  nowSeconds = Math.floor(Date.now() / 1000)
): RateLimitResetExpiryStatus {
  if (typeof expiresAt !== "number") return "no-expiry"
  if (expiresAt <= nowSeconds) return "expired"
  return expiresAt - nowSeconds <= 24 * 60 * 60 ? "expires-soon" : "active"
}
