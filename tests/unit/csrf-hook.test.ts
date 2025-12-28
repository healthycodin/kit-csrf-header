import { describe, it, expect, vi, beforeEach } from 'vitest';
import { csrfProtection } from '../../src/lib/csrf-hook.js';
import { createMockEvent } from '../helpers/mock-event.js';

describe('csrfProtection hook', () => {
	const mockResolve = vi.fn(async () => new Response('OK'));

	beforeEach(() => {
		vi.clearAllMocks();
	});

	describe('GET requests', () => {
		it('allows GET requests without any checks', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({ method: 'GET' });

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalledWith(event);
		});

		it('allows HEAD requests without any checks', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({ method: 'HEAD' });

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('allows OPTIONS requests without any checks', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({ method: 'OPTIONS' });

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});
	});

	describe('POST requests with Sec-Fetch-Site', () => {
		it('allows same-origin requests', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'same-origin' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('allows none (user-initiated) requests', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'none' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('rejects cross-site requests with 403', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(mockResolve).not.toHaveBeenCalled();
			expect(response.status).toBe(403);
		});

		it('rejects same-site by default', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'same-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});

		it('allows same-site when configured', async () => {
			const hook = csrfProtection({ allowSameSite: true });
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'same-site' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});
	});

	describe('other state-changing methods', () => {
		it('protects PUT requests', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'PUT',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});

		it('protects DELETE requests', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'DELETE',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});

		it('protects PATCH requests', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'PATCH',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});
	});

	describe('Origin header fallback', () => {
		it('allows matching origin when Sec-Fetch-Site missing', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				origin: 'http://localhost:5173',
				headers: { Origin: 'http://localhost:5173' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('allows configured allowed origins', async () => {
			const hook = csrfProtection({
				allowedOrigins: ['https://trusted.com']
			});
			const event = createMockEvent({
				method: 'POST',
				headers: { Origin: 'https://trusted.com' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('rejects unknown origins', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: { Origin: 'https://evil.com' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});

		it('allows requests with no Origin header (legacy browsers)', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: {} // No Origin, no Sec-Fetch-Site
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});
	});

	describe('path configuration', () => {
		it('skips protection for excluded paths', async () => {
			const hook = csrfProtection({
				excludePaths: ['/api/webhooks']
			});
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/webhooks/stripe',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('protects non-excluded paths', async () => {
			const hook = csrfProtection({
				excludePaths: ['/api/webhooks']
			});
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/users',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});

		it('only protects specified paths when protectPaths set', async () => {
			const hook = csrfProtection({
				protectPaths: ['/api/admin']
			});
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/public',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});

		it('protects paths in protectPaths list', async () => {
			const hook = csrfProtection({
				protectPaths: ['/api/admin']
			});
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/admin/users',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(response.status).toBe(403);
		});

		it('excludePaths takes precedence over protectPaths', async () => {
			const hook = csrfProtection({
				protectPaths: ['/api'],
				excludePaths: ['/api/webhooks']
			});
			const event = createMockEvent({
				method: 'POST',
				pathname: '/api/webhooks/stripe',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			await hook({ event, resolve: mockResolve });

			expect(mockResolve).toHaveBeenCalled();
		});
	});

	describe('custom rejection handler', () => {
		it('uses custom onReject handler', async () => {
			const customHandler = vi.fn(() => new Response('Custom Error', { status: 400 }));
			const hook = csrfProtection({ onReject: customHandler });
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });

			expect(customHandler).toHaveBeenCalledWith(event, 'cross-site');
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Custom Error');
		});

		it('passes correct rejection reason to onReject', async () => {
			const customHandler = vi.fn(() => new Response('', { status: 403 }));
			const hook = csrfProtection({ onReject: customHandler });
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'same-site' }
			});

			await hook({ event, resolve: mockResolve });

			expect(customHandler).toHaveBeenCalledWith(event, 'same-site-not-allowed');
		});
	});

	describe('response format', () => {
		it('returns JSON for application/json accept header', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: {
					'Sec-Fetch-Site': 'cross-site',
					Accept: 'application/json'
				}
			});

			const response = await hook({ event, resolve: mockResolve });
			const body = await response.json();

			expect(response.headers.get('content-type')).toContain('application/json');
			expect(body).toHaveProperty('error', 'CSRF_REJECTED');
			expect(body).toHaveProperty('message');
			expect(body).toHaveProperty('reason', 'cross-site');
		});

		it('returns text for other accept headers', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: { 'Sec-Fetch-Site': 'cross-site' }
			});

			const response = await hook({ event, resolve: mockResolve });
			const text = await response.text();

			expect(text).toContain('CSRF');
		});

		it('returns text for text/html accept header', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: {
					'Sec-Fetch-Site': 'cross-site',
					Accept: 'text/html'
				}
			});

			const response = await hook({ event, resolve: mockResolve });
			const text = await response.text();

			const contentType = response.headers.get('content-type') || '';
			expect(contentType).not.toContain('application/json');
			expect(text).toContain('CSRF');
		});
	});

	describe('error messages', () => {
		it('provides meaningful error for cross-site', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: {
					'Sec-Fetch-Site': 'cross-site',
					Accept: 'application/json'
				}
			});

			const response = await hook({ event, resolve: mockResolve });
			const body = await response.json();

			expect(body.message.toLowerCase()).toContain('cross-site');
		});

		it('provides meaningful error for same-site rejection', async () => {
			const hook = csrfProtection();
			const event = createMockEvent({
				method: 'POST',
				headers: {
					'Sec-Fetch-Site': 'same-site',
					Accept: 'application/json'
				}
			});

			const response = await hook({ event, resolve: mockResolve });
			const body = await response.json();

			expect(body.message).toContain('subdomain');
		});
	});
});
