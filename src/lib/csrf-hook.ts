import { createRejectionResponse } from "./response.js";
import type { CsrfHookFactory, Handle, SecFetchSiteValue } from "./types.js";
import {
  isPathExcluded,
  isPathProtected,
  isStateChangingMethod,
  validateOrigin,
  validateSecFetchSite,
} from "./validators.js";

const DEFAULT_CONFIG = {
  allowSameSite: false,
  allowedOrigins: [] as string[],
  excludePaths: [] as string[],
};

/**
 * Create a CSRF protection hook using Sec-Fetch-Site header
 *
 * @example
 * ```typescript
 * // hooks.server.ts
 * import { sequence } from '@sveltejs/kit/hooks';
 * import { csrfProtection } from 'kit-csrf-header';
 *
 * export const handle = sequence(
 *   csrfProtection({
 *     allowSameSite: false,
 *     excludePaths: ['/api/webhooks'],
 *   })
 * );
 * ```
 */
export const csrfProtection: CsrfHookFactory = (config = {}) => {
  const {
    allowSameSite = DEFAULT_CONFIG.allowSameSite,
    allowedOrigins = DEFAULT_CONFIG.allowedOrigins,
    excludePaths = DEFAULT_CONFIG.excludePaths,
    protectPaths,
    onReject,
  } = config;

  const handle: Handle = async ({ event, resolve }) => {
    const { request, url } = event;
    const method = request.method;

    // Only check state-changing methods
    if (!isStateChangingMethod(method)) {
      return resolve(event);
    }

    // Check path exclusions first (takes precedence)
    if (isPathExcluded(url.pathname, excludePaths)) {
      return resolve(event);
    }

    // Check if path should be protected
    if (!isPathProtected(url.pathname, protectPaths)) {
      return resolve(event);
    }

    // Try Sec-Fetch-Site header first (modern browsers)
    const secFetchSite = request.headers.get(
      "sec-fetch-site"
    ) as SecFetchSiteValue | null;

    if (secFetchSite) {
      const result = validateSecFetchSite(secFetchSite, allowSameSite);

      if (result.allowed) {
        return resolve(event);
      }

      // Rejected by Sec-Fetch-Site
      if (onReject) {
        return onReject(event, result.reason!);
      }
      return createRejectionResponse(event, result.reason!);
    }

    // Fallback to Origin header for older browsers
    const origin = request.headers.get("origin");
    const result = validateOrigin(origin, url.origin, allowedOrigins);

    if (result.allowed) {
      return resolve(event);
    }

    // Rejected by Origin check
    if (onReject) {
      return onReject(event, result.reason!);
    }
    return createRejectionResponse(event, result.reason!);
  };

  return handle;
};
