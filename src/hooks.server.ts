import { sequence } from '@sveltejs/kit/hooks';
import { csrfProtection } from '$lib/index.js';

/**
 * Example CSRF protection configuration
 *
 * This demonstrates how to use the csrfProtection hook in a SvelteKit app.
 */
const csrf = csrfProtection({
	// Reject requests from subdomains by default (more secure)
	allowSameSite: false,

	// Allow these origins when Sec-Fetch-Site header is missing (older browsers)
	allowedOrigins: [
		'http://localhost:5173',
		'http://localhost:4173' // preview server
	],

	// Skip CSRF protection for these paths (useful for webhooks)
	excludePaths: ['/api/webhooks']
});

export const handle = sequence(csrf);
