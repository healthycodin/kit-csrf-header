import type { RequestEvent } from "@sveltejs/kit";
import { json, text } from "@sveltejs/kit";
import type { CsrfRejectionReason } from "./types.js";

const ERROR_MESSAGES: Record<CsrfRejectionReason, string> = {
  "cross-site": "Cross-site requests are not allowed",
  "same-site-not-allowed": "Same-site requests from subdomains are not allowed",
  "origin-not-allowed": "Request origin is not in the allowed list",
  "missing-origin-and-sec-fetch-site": "Unable to verify request origin",
};

/**
 * Create a rejection response with appropriate content type
 */
export function createRejectionResponse(
  event: RequestEvent,
  reason: CsrfRejectionReason
): Response {
  const message = ERROR_MESSAGES[reason];
  const acceptHeader = event.request.headers.get("accept") || "";

  if (acceptHeader.includes("application/json")) {
    return json(
      {
        error: "CSRF_REJECTED",
        message,
        reason,
      },
      { status: 403 }
    );
  }

  return text(`CSRF Protection: ${message}`, { status: 403 });
}
