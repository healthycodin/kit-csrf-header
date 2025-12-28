import type { CsrfValidationResult, SecFetchSiteValue } from "./types.js";

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

/**
 * Check if an HTTP method is state-changing (requires CSRF protection)
 */
export function isStateChangingMethod(method: string): boolean {
  return STATE_CHANGING_METHODS.has(method.toUpperCase());
}

/**
 * Validate the Sec-Fetch-Site header value
 */
export function validateSecFetchSite(
  value: SecFetchSiteValue,
  allowSameSite: boolean
): CsrfValidationResult {
  // Always allow same-origin and none (user-initiated like typing URL)
  if (value === "same-origin" || value === "none") {
    return { allowed: true, source: "sec-fetch-site" };
  }

  // Same-site: configurable (default reject for security)
  if (value === "same-site") {
    if (allowSameSite) {
      return { allowed: true, source: "sec-fetch-site" };
    }
    return {
      allowed: false,
      reason: "same-site-not-allowed",
      source: "sec-fetch-site",
    };
  }

  // Cross-site: always reject
  return {
    allowed: false,
    reason: "cross-site",
    source: "sec-fetch-site",
  };
}

/**
 * Validate the Origin header as fallback when Sec-Fetch-Site is not available
 */
export function validateOrigin(
  requestOrigin: string | null,
  urlOrigin: string,
  allowedOrigins: string[]
): CsrfValidationResult {
  // No origin header = legacy browser, allow (can't be CSRF from modern browser)
  if (!requestOrigin) {
    return { allowed: true, source: "origin-fallback" };
  }

  // Same origin - always allowed
  if (requestOrigin === urlOrigin) {
    return { allowed: true, source: "origin-fallback" };
  }

  // Check allowed origins list
  if (allowedOrigins.includes(requestOrigin)) {
    return { allowed: true, source: "origin-fallback" };
  }

  return {
    allowed: false,
    reason: "origin-not-allowed",
    source: "origin-fallback",
  };
}

/**
 * Check if a path should be excluded from CSRF protection
 */
export function isPathExcluded(
  pathname: string,
  excludePaths: string[]
): boolean {
  return excludePaths.some((excludePath) => {
    // Exact match
    if (pathname === excludePath) return true;
    // Prefix match with path separator (prevents /api/webhooks matching /api/webhooks-new)
    if (pathname.startsWith(excludePath + "/")) return true;
    return false;
  });
}

/**
 * Check if a path should be protected (when protectPaths is configured)
 */
export function isPathProtected(
  pathname: string,
  protectPaths: string[] | undefined
): boolean {
  // If not configured, protect all paths
  if (protectPaths === undefined) return true;

  // If empty array, nothing specific is protected (so nothing matches)
  if (protectPaths.length === 0) return false;

  return protectPaths.some((protectPath) => {
    // Exact match
    if (pathname === protectPath) return true;
    // Prefix match with path separator
    if (pathname.startsWith(protectPath + "/")) return true;
    return false;
  });
}
