// CSRF Protection Hook for SvelteKit
// Uses Sec-Fetch-Site header with Origin fallback

export { csrfProtection } from "./csrf-hook.js";

export type {
  CsrfConfig,
  CsrfHookFactory,
  CsrfRejectionReason,
  CsrfValidationResult,
  SecFetchSiteValue,
} from "./types.js";
