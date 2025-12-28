import { describe, it, expect, vi } from 'vitest';
import { csrfProtection } from '../../src/lib/csrf-hook.js';
import { createMockEvent } from '../helpers/mock-event.js';

describe('CSRF hook integration', () => {
	// Note: Tests using sequence() from @sveltejs/kit/hooks require
	// the full SvelteKit runtime context and cannot be unit tested.
	// The hook is designed to work with sequence() - see src/hooks.server.ts for usage.

	describe('real-world scenarios', () => {
		it('handles form submission from same origin', async () => {
			const csrf = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/users',
				origin: 'https://myapp.com',
				headers: {
					'Sec-Fetch-Site': 'same-origin',
					'Content-Type': 'application/x-www-form-urlencoded'
				}
			});

			const resolve = vi.fn(async () => new Response('Created', { status: 201 }));
			await csrf({ event, resolve });

			expect(resolve).toHaveBeenCalled();
		});

		it('blocks cross-origin fetch API call', async () => {
			const csrf = csrfProtection();
			const event = createMockEvent({
				method: 'DELETE',
				pathname: '/api/users/123',
				headers: {
					'Sec-Fetch-Site': 'cross-site',
					'Content-Type': 'application/json'
				}
			});

			const resolve = vi.fn(async () => new Response('Deleted'));
			const response = await csrf({ event, resolve });

			expect(response.status).toBe(403);
			expect(resolve).not.toHaveBeenCalled();
		});

		it('allows webhook from excluded path', async () => {
			const csrf = csrfProtection({
				excludePaths: ['/api/webhooks']
			});
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/webhooks/stripe',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const resolve = vi.fn(async () => new Response('OK'));
			await csrf({ event, resolve });

			expect(resolve).toHaveBeenCalled();
		});

		it('protects API while allowing static pages', async () => {
			const csrf = csrfProtection({
				protectPaths: ['/api']
			});

			// Static page should pass through
			const pageEvent = createMockEvent({
				method: 'POST',
				pathname: '/contact',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const pageResolve = vi.fn(async () => new Response('OK'));
			await csrf({ event: pageEvent, resolve: pageResolve });
			expect(pageResolve).toHaveBeenCalled();

			// API should be protected
			const apiEvent = createMockEvent({
				method: 'POST',
				pathname: '/api/contact',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const apiResolve = vi.fn(async () => new Response('OK'));
			const response = await csrf({ event: apiEvent, resolve: apiResolve });
			expect(response.status).toBe(403);
		});

		it('handles subdomain requests correctly', async () => {
			// Default: reject same-site (subdomains)
			const strictCsrf = csrfProtection();
			const strictEvent = createMockEvent({
				method: 'POST',
				origin: 'https://app.example.com',
				headers: { 'Sec-Fetch-Site': 'same-site' }
			});

			const strictResponse = await strictCsrf({
				event: strictEvent,
				resolve: async () => new Response('OK')
			});
			expect(strictResponse.status).toBe(403);

			// With allowSameSite: allow subdomains
			const relaxedCsrf = csrfProtection({ allowSameSite: true });
			const relaxedEvent = createMockEvent({
				method: 'POST',
				origin: 'https://app.example.com',
				headers: { 'Sec-Fetch-Site': 'same-site' }
			});

			const relaxedResolve = vi.fn(async () => new Response('OK'));
			await relaxedCsrf({ event: relaxedEvent, resolve: relaxedResolve });
			expect(relaxedResolve).toHaveBeenCalled();
		});
	});
});
