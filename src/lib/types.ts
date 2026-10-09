import type { RequestEvent } from "@sveltejs/kit";
import type { sequence } from "@sveltejs/kit/hooks";

// Derived from `sequence` because `Handle` is exported from different modules in Kit 2 and Kit 3.
export type Handle = Parameters<typeof sequence>[0];

/**
 * Sec-Fetch-Site header values as defined by the Fetch Metadata spec
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
 */
export type SecFetchSiteValue =
  | "same-origin"
  | "same-site"
  | "cross-site"
  | "none";

/**
 * HTTP methods that change server state and require CSRF protection
 */
export type StateChangingMethod = "POST" | "PUT" | "DELETE" | "PATCH";

/**
 * Reasons why a request might be rejected by CSRF protection
 */
export type CsrfRejectionReason =
  | "cross-site"
  | "same-site-not-allowed"
  | "origin-not-allowed"
  | "missing-origin-and-sec-fetch-site";

/**
 * Result of CSRF validation
 */
export interface CsrfValidationResult {
  allowed: boolean;
  reason?: CsrfRejectionReason;
  source: "sec-fetch-site" | "origin-fallback" | "skipped";
}

/**
 * Configuration options for the CSRF protection hook
 */
export interface CsrfConfig {
  /**
   * Whether to allow same-site requests (different subdomains of the same domain)
   * Default: false (more secure - blocks subdomain requests)
   */
  allowSameSite?: boolean;

  /**
   * List of allowed origins for fallback Origin header check
   * Used when Sec-Fetch-Site header is missing (older browsers)
   * Example: ['https://trusted.com', 'https://api.trusted.com']
   */
  allowedOrigins?: string[];

  /**
   * Paths to exclude from CSRF protection
   * Useful for webhooks that need to receive cross-origin requests
   * Supports exact match and prefix match with path separator
   * Example: ['/api/webhooks', '/api/public']
   */
  excludePaths?: string[];

  /**
   * Paths to explicitly protect (if set, only these paths are protected)
   * If not set, all state-changing requests are protected by default
   * Example: ['/api/admin', '/api/users']
   */
  protectPaths?: string[];

  /**
   * Custom handler for rejected requests
   * Default: Returns 403 with appropriate message (JSON or text based on Accept header)
   */
  onReject?: (event: RequestEvent, reason: CsrfRejectionReason) => Response;
}

/**
 * Factory function type for creating CSRF hook
 */
export type CsrfHookFactory = (config?: CsrfConfig) => Handle;
