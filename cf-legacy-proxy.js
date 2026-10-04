export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS' && request.headers.has('Origin')) {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': '*',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    const rawTarget = env.TARGET_DOMAIN;
    if (!rawTarget) return new Response('Missing TARGET_DOMAIN', { status: 500 });

    const targetDomain = rawTarget.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    const [targetHost, targetPort] = targetDomain.split(':');

    const url = new URL(request.url);
    const originalHost = url.host;
    url.hostname = targetHost;
    url.protocol = 'https:';
    url.port = targetPort || '';

    const headers = new Headers(request.headers);
    headers.set('Host', targetHost);
    headers.set('X-Forwarded-Host', originalHost);
    headers.set('X-Forwarded-Proto', 'http');
    headers.set('Accept-Encoding', 'gzip, deflate');
    headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || 'unknown-ip');
    headers.delete('CF-Connecting-IP');

    if (request.cf) {
      headers.set('X-Real-Country', request.cf.country || '');
      headers.set('X-Real-Region', request.cf.region || '');
      headers.set('X-Real-City', request.cf.city || '');
    }

    const isBodyMethod = request.method !== 'GET' && request.method !== 'HEAD';
    const response = await fetch(url.toString(), {
      method: request.method,
      headers,
      body: isBodyMethod ? request.body : null,
      redirect: 'manual',
      ...(isBodyMethod ? { duplex: 'half' } : {})
    });

    let res = new Response(response.body, response);

    const location = res.headers.get('Location');
    if (location) {
      try {
        const loc = new URL(location, `https://${targetDomain}`);
        if (loc.hostname === targetHost) {
          loc.protocol = 'http:';
          loc.host = originalHost;
          res.headers.set('Location', loc.toString());
        }
      } catch {
        const escaped = targetDomain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        res.headers.set('Location', location.replace(new RegExp(`https?://${escaped}(?=[/?#]|$)`, 'gi'), `http://${originalHost}`));
      }
    }

    res.headers.delete('Strict-Transport-Security');
    res.headers.delete('Content-Security-Policy');
    res.headers.delete('Content-Security-Policy-Report-Only');

    const rawCookies = res.headers.getSetCookie?.() || (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
    if (rawCookies.length) {
      res.headers.delete('Set-Cookie');
      for (const c of rawCookies) {
        res.headers.append('Set-Cookie', c
          .replace(/;\s*Domain=[^;]+/gi, '')
          .replace(/;\s*Secure/gi, '')
          .replace(/;\s*SameSite=None/gi, '; SameSite=Lax')
        );
      }
    }

    const ct = res.headers.get('content-type') || '';
    if (/html|wml|xhtml|text\/css/i.test(ct)) {
      const escaped = targetDomain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const domainRegex = new RegExp(`(?:https?:)?//${escaped}(?=[/?#"')\\s]|$)`, 'gi');

      let text = (await res.text()).replace(domainRegex, `http://${originalHost}`);
      if (/html|wml|xhtml/i.test(ct)) {
        text = text.replace(/<meta[^>]*http-equiv=["']?Content-Security-Policy["']?[^>]*>/gi, '');
      }

      const h = new Headers(res.headers);
      h.delete('content-length');
      h.delete('content-encoding');
      res = new Response(text, { status: res.status, statusText: res.statusText, headers: h });
    }

    res.headers.set('Access-Control-Allow-Origin', '*');
    res.headers.set('Access-Control-Allow-Methods', '*');
    res.headers.set('Access-Control-Allow-Headers', '*');

    return res;
  }
};
