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

    const targetProto = /^http:\/\//i.test(rawTarget) ? 'http:' : 'https:';
    const targetDomain = rawTarget.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    const [targetHost, targetPort = ''] = targetDomain.split(':');

    const url = new URL(request.url);
    const { hostname: origHostname, port: origPort, host: originalHost } = url;

    url.hostname = targetHost;
    url.protocol = targetProto;
    url.port = targetPort;

    const headers = new Headers(request.headers);
    headers.set('Host', targetDomain);
    headers.set('X-Forwarded-Host', originalHost);
    headers.set('X-Forwarded-Proto', targetProto === 'http:' ? 'http' : 'https');
    headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || 'unknown-ip');
    headers.delete('CF-Connecting-IP');

    const clientAE = request.headers.get('accept-encoding') || '';
    headers.set('Accept-Encoding', clientAE.includes('gzip') ? 'gzip, deflate' : 'identity');

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
          loc.hostname = origHostname;
          loc.port = origPort;
          res.headers.set('Location', loc.toString());
        }
      } catch {
        const escaped = targetHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        res.headers.set('Location', location.replace(new RegExp(`https?://${escaped}(?::\\d+)?(?=[/?#]|$)`, 'gi'), `http://${originalHost}`));
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
          .replace(/;\s*Domain=[^;]*/gi, '')
          .replace(/;\s*Secure\b/gi, '')
          .replace(/;\s*SameSite=None/gi, '; SameSite=Lax')
        );
      }
    }

    const ct = res.headers.get('content-type') || '';
    if (![101, 204, 205, 304].includes(res.status) && /html|wml|xhtml|text\/css|javascript|json|xml/i.test(ct)) {
      const arrayBuf = await res.arrayBuffer();

      let charset = ct.match(/charset=([^;]+)/i)?.[1]?.trim().toLowerCase();
      if (!charset && /html|wml|xhtml|xml/i.test(ct)) {
        const preview = new TextDecoder('latin1').decode(arrayBuf.slice(0, 1024));
        const metaMatch = preview.match(/<meta[^>]+charset=["']?([a-zA-Z0-9_-]+)/i) ||
                          preview.match(/<meta[^>]+content=["'][^"']*charset=([a-zA-Z0-9_-]+)/i);
        if (metaMatch) charset = metaMatch[1].trim().toLowerCase();
      }
      charset = charset || 'utf-8';

      let text;
      try {
        text = new TextDecoder(charset).decode(arrayBuf);
      } catch {
        text = new TextDecoder('utf-8').decode(arrayBuf);
      }

      const escapedHost = targetHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const portPattern = targetPort ? `(?::${targetPort})?` : '(?::\\d+)?';
      const domainRegex = new RegExp(`(?:https?:)?(\\\\/\\\\/|//)${escapedHost}${portPattern}(?=[/?#"')\\\\\\s<>]|$)`, 'gi');
      text = text.replace(domainRegex, (_, slashes) => `http:${slashes}${originalHost}`);

      if (/html|wml|xhtml/i.test(ct)) {
        text = text
          .replace(/<meta[^>]*http-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*>/gi, '')
          .replace(/(<meta[^>]+content=["'][^"']*charset=)[a-zA-Z0-9_-]+(["'])/gi, '$1utf-8$2')
          .replace(/(<meta[^>]+charset=["']?)[a-zA-Z0-9_-]+(["']?)/gi, '$1utf-8$2');
      }

      const encoded = new TextEncoder().encode(text);
      const h = new Headers(res.headers);
      h.delete('content-encoding');
      h.set('content-length', encoded.byteLength.toString());
      h.set('content-type', ct.includes('charset=') ? ct.replace(/charset=[^;]+/i, 'charset=utf-8') : `${ct}; charset=utf-8`);

      res = new Response(encoded, { status: res.status, statusText: res.statusText, headers: h });
    }

    res.headers.set('Access-Control-Allow-Origin', '*');
    res.headers.set('Access-Control-Allow-Methods', '*');
    res.headers.set('Access-Control-Allow-Headers', '*');

    return res;
  }
};
