# @healthycodin/kit-csrf-header

CSRF protection for SvelteKit using the `Sec-Fetch-Site` header with Origin fallback.

## Why?

SvelteKit's built-in CSRF protection only covers **form submissions**. Modern SPAs often use `fetch()` with JSON APIs, which bypasses that protection.

This hook uses the `Sec-Fetch-Site` header—a browser-set header that **cannot be spoofed by JavaScript**—to protect all state-changing requests.

| Feature | SvelteKit Built-in | This Hook |
|---------|-------------------|-----------|
| Protects forms | ✅ | ✅ |
| Protects JSON APIs | ❌ | ✅ |
| Header used | Origin | Sec-Fetch-Site + Origin fallback |
| Spoofable | Origin can be omitted | Sec-Fetch-Site cannot be forged |
| Subdomain control | ❌ | ✅ |

## Installation

```bash
npm install @healthycodin/kit-csrf-header
```

> **Note:** For GitHub Packages, you need to authenticate. Add to your `.npmrc`:
> ```
> @healthycodin:registry=https://npm.pkg.github.com
> //npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
> ```

## Usage

```typescript
// src/hooks.server.ts
import { sequence } from '@sveltejs/kit/hooks';
import { csrfProtection } from '@healthycodin/kit-csrf-header';

export const handle = sequence(
  csrfProtection({
    // Reject requests from subdomains (default: false)
    allowSameSite: false,

    // Skip protection for these paths (e.g., webhooks)
    excludePaths: ['/api/webhooks'],
  })
);
```

## Configuration

```typescript
interface CsrfConfig {
  // Allow requests from subdomains (same-site)
  // Default: false (more secure)
  allowSameSite?: boolean;

  // Trusted origins for Origin header fallback (older browsers)
  // Example: ['https://trusted.com']
  allowedOrigins?: string[];

  // Paths to exclude from protection
  // Example: ['/api/webhooks', '/api/public']
  excludePaths?: string[];

  // Only protect these paths (if set)
  // Example: ['/api/admin', '/api/users']
  protectPaths?: string[];

  // Custom rejection handler
  // Default: Returns 403 with JSON or text based on Accept header
  onReject?: (event: RequestEvent, reason: CsrfRejectionReason) => Response;
}
```

## How It Works

1. **State-changing requests only** — GET, HEAD, OPTIONS pass through
2. **Check `Sec-Fetch-Site` header** (modern browsers):
   - `same-origin` → ✅ Allow
   - `none` (user-initiated, e.g., typing URL) → ✅ Allow
   - `same-site` → ❌ Reject (unless `allowSameSite: true`)
   - `cross-site` → ❌ Reject
3. **Fallback to `Origin` header** (older browsers):
   - Matches request URL origin → ✅ Allow
   - In `allowedOrigins` list → ✅ Allow
   - Otherwise → ❌ Reject
4. **No headers** (legacy browsers) → ✅ Allow (can't be CSRF from modern browser)

## Rejection Response

When a request is rejected, the hook returns a 403 response:

**For `Accept: application/json`:**
```json
{
  "error": "CSRF_REJECTED",
  "message": "Cross-site requests are not allowed",
  "reason": "cross-site"
}
```

**For other requests:**
```
CSRF Protection: Cross-site requests are not allowed
```

## Skipping in Development

The hook runs in all environments. To skip in dev:

```typescript
import { dev } from '$app/environment';
import { csrfProtection } from '@healthycodin/kit-csrf-header';

const csrf = csrfProtection({ ... });

export const handle = dev
  ? ({ event, resolve }) => resolve(event)
  : csrf;
```

## Browser Support

`Sec-Fetch-Site` is supported in:
- Chrome 76+
- Firefox 90+
- Safari 16.4+
- Edge 79+

Older browsers fall back to Origin header validation.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests once
npm run test:run

# Type check
npm run check

# Build package
npm run build
```

## License

MIT
