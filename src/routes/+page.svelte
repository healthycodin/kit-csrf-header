<h1>@healthycodin/kit-csrf-header</h1>
<p>CSRF protection for SvelteKit using Sec-Fetch-Site header.</p>

<h2>Usage</h2>
<pre>
{`// hooks.server.ts
import { sequence } from '@sveltejs/kit/hooks';
import { csrfProtection } from '@healthycodin/kit-csrf-header';

export const handle = sequence(
  csrfProtection({
    allowSameSite: false,
    excludePaths: ['/api/webhooks'],
  })
);`}
</pre>
