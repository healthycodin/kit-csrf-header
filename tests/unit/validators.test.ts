import { describe, it, expect } from 'vitest';
import {
	isStateChangingMethod,
	validateSecFetchSite,
	validateOrigin,
	isPathExcluded,
	isPathProtected
} from '../../src/lib/validators.js';

describe('isStateChangingMethod', () => {
	it('returns true for POST', () => {
		expect(isStateChangingMethod('POST')).toBe(true);
	});

	it('returns true for PUT', () => {
		expect(isStateChangingMethod('PUT')).toBe(true);
	});

	it('returns true for DELETE', () => {
		expect(isStateChangingMethod('DELETE')).toBe(true);
	});

	it('returns true for PATCH', () => {
		expect(isStateChangingMethod('PATCH')).toBe(true);
	});

	it('returns false for GET', () => {
		expect(isStateChangingMethod('GET')).toBe(false);
	});

	it('returns false for HEAD', () => {
		expect(isStateChangingMethod('HEAD')).toBe(false);
	});

	it('returns false for OPTIONS', () => {
		expect(isStateChangingMethod('OPTIONS')).toBe(false);
	});

	it('handles lowercase methods', () => {
		expect(isStateChangingMethod('post')).toBe(true);
		expect(isStateChangingMethod('get')).toBe(false);
	});
});

describe('validateSecFetchSite', () => {
	describe('with allowSameSite: false (default)', () => {
		it('allows same-origin', () => {
			const result = validateSecFetchSite('same-origin', false);
			expect(result.allowed).toBe(true);
			expect(result.source).toBe('sec-fetch-site');
		});

		it('allows none (user-initiated)', () => {
			const result = validateSecFetchSite('none', false);
			expect(result.allowed).toBe(true);
			expect(result.source).toBe('sec-fetch-site');
		});

		it('rejects same-site', () => {
			const result = validateSecFetchSite('same-site', false);
			expect(result.allowed).toBe(false);
			expect(result.reason).toBe('same-site-not-allowed');
			expect(result.source).toBe('sec-fetch-site');
		});

		it('rejects cross-site', () => {
			const result = validateSecFetchSite('cross-site', false);
			expect(result.allowed).toBe(false);
			expect(result.reason).toBe('cross-site');
			expect(result.source).toBe('sec-fetch-site');
		});
	});

	describe('with allowSameSite: true', () => {
		it('allows same-site', () => {
			const result = validateSecFetchSite('same-site', true);
			expect(result.allowed).toBe(true);
			expect(result.source).toBe('sec-fetch-site');
		});

		it('still rejects cross-site', () => {
			const result = validateSecFetchSite('cross-site', true);
			expect(result.allowed).toBe(false);
			expect(result.reason).toBe('cross-site');
		});

		it('still allows same-origin', () => {
			const result = validateSecFetchSite('same-origin', true);
			expect(result.allowed).toBe(true);
		});

		it('still allows none', () => {
			const result = validateSecFetchSite('none', true);
			expect(result.allowed).toBe(true);
		});
	});
});

describe('validateOrigin', () => {
	it('allows matching origin', () => {
		const result = validateOrigin('http://localhost:5173', 'http://localhost:5173', []);
		expect(result.allowed).toBe(true);
		expect(result.source).toBe('origin-fallback');
	});

	it('allows origin in allowedOrigins list', () => {
		const result = validateOrigin('https://trusted.com', 'http://localhost:5173', [
			'https://trusted.com'
		]);
		expect(result.allowed).toBe(true);
		expect(result.source).toBe('origin-fallback');
	});

	it('allows origin with multiple allowed origins', () => {
		const result = validateOrigin('https://api.trusted.com', 'http://localhost:5173', [
			'https://trusted.com',
			'https://api.trusted.com'
		]);
		expect(result.allowed).toBe(true);
	});

	it('rejects origin not in allowedOrigins', () => {
		const result = validateOrigin('https://evil.com', 'http://localhost:5173', [
			'https://trusted.com'
		]);
		expect(result.allowed).toBe(false);
		expect(result.reason).toBe('origin-not-allowed');
		expect(result.source).toBe('origin-fallback');
	});

	it('allows null origin (legacy browsers without Origin header)', () => {
		const result = validateOrigin(null, 'http://localhost:5173', []);
		expect(result.allowed).toBe(true);
		expect(result.source).toBe('origin-fallback');
	});

	it('rejects different port as different origin', () => {
		const result = validateOrigin('http://localhost:3000', 'http://localhost:5173', []);
		expect(result.allowed).toBe(false);
		expect(result.reason).toBe('origin-not-allowed');
	});

	it('rejects different protocol as different origin', () => {
		const result = validateOrigin('https://localhost:5173', 'http://localhost:5173', []);
		expect(result.allowed).toBe(false);
		expect(result.reason).toBe('origin-not-allowed');
	});
});

describe('isPathExcluded', () => {
	it('matches exact path', () => {
		expect(isPathExcluded('/api/webhooks', ['/api/webhooks'])).toBe(true);
	});

	it('matches path prefix with slash', () => {
		expect(isPathExcluded('/api/webhooks/stripe', ['/api/webhooks'])).toBe(true);
	});

	it('matches deeply nested path', () => {
		expect(isPathExcluded('/api/webhooks/stripe/events', ['/api/webhooks'])).toBe(true);
	});

	it('does not match partial path name', () => {
		expect(isPathExcluded('/api/webhooks-new', ['/api/webhooks'])).toBe(false);
	});

	it('does not match similar but different paths', () => {
		expect(isPathExcluded('/api/webhook', ['/api/webhooks'])).toBe(false);
	});

	it('returns false for non-excluded paths', () => {
		expect(isPathExcluded('/api/users', ['/api/webhooks'])).toBe(false);
	});

	it('returns false for empty exclude list', () => {
		expect(isPathExcluded('/api/users', [])).toBe(false);
	});

	it('handles multiple exclude paths', () => {
		const excludePaths = ['/api/webhooks', '/api/public'];
		expect(isPathExcluded('/api/webhooks/stripe', excludePaths)).toBe(true);
		expect(isPathExcluded('/api/public/data', excludePaths)).toBe(true);
		expect(isPathExcluded('/api/private', excludePaths)).toBe(false);
	});
});

describe('isPathProtected', () => {
	it('returns true when protectPaths is undefined', () => {
		expect(isPathProtected('/api/users', undefined)).toBe(true);
	});

	it('returns true when protectPaths is empty array (protects nothing specific = protect all)', () => {
		expect(isPathProtected('/api/users', [])).toBe(false);
	});

	it('matches exact path', () => {
		expect(isPathProtected('/api/users', ['/api/users'])).toBe(true);
	});

	it('matches path prefix with slash', () => {
		expect(isPathProtected('/api/users/123', ['/api/users'])).toBe(true);
	});

	it('does not match partial path name', () => {
		expect(isPathProtected('/api/usersettings', ['/api/users'])).toBe(false);
	});

	it('returns false for non-protected paths when protectPaths is set', () => {
		expect(isPathProtected('/api/public', ['/api/users', '/api/admin'])).toBe(false);
	});

	it('handles multiple protect paths', () => {
		const protectPaths = ['/api/admin', '/api/users'];
		expect(isPathProtected('/api/admin/settings', protectPaths)).toBe(true);
		expect(isPathProtected('/api/users/123', protectPaths)).toBe(true);
		expect(isPathProtected('/api/public', protectPaths)).toBe(false);
	});
});
