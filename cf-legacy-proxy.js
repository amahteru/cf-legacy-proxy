const TEXT_MIME = /^(?:text\/(?:html|css|javascript|ecmascript|xml|vnd\.wap\.wml|vnd\.wap\.wmlscript)|application\/(?:xhtml\+xml|vnd\.wap\.xhtml\+xml|xml|json|javascript|x-javascript|ecmascript)|[a-z0-9.+-]+\/[a-z0-9.-]+\+(?:xml|json))$/;

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

    const targetUrl = new URL(rawTarget.includes('://') ? rawTarget : `https://${rawTarget}`);
    const { protocol: targetProto, hostname: targetHost, port: targetPort, host: targetDomain } = targetUrl;
    const baseHost = targetHost.replace(/^www\./i, '');
    const escapedHost = baseHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const url = new URL(request.url);
    const { hostname: origHostname, port: origPort, host: originalHost, protocol: origProto } = url;

    url.hostname = targetHost;
    url.protocol = targetProto;
    url.port = targetPort;

    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown-ip';
    const headers = new Headers(request.headers);
    headers.set('Host', targetDomain);
    headers.set('X-Forwarded-Host', originalHost);
    headers.set('X-Forwarded-Proto', origProto === 'http:' ? 'http' : 'https');
    headers.set('X-Real-IP', clientIP);
    headers.set('X-Forwarded-For', clientIP);
    headers.delete('CF-Connecting-IP');

    const clientAE = request.headers.get('accept-encoding') || '';

    if (request.cf) {
      headers.set('X-Real-Country', request.cf.country || '');
      headers.set('X-Real-Region', request.cf.region || '');
      headers.set('X-Real-City', request.cf.city || '');
    }

    const isBodyMethod = request.method !== 'GET' && request.method !== 'HEAD';
    let response;
    try {
      response = await fetch(url.toString(), {
        method: request.method,
        headers,
        body: isBodyMethod ? request.body : null,
        redirect: 'manual'
      });
    } catch (err) {
      return new Response(`Bad Gateway: ${err.message}`, {
        status: 502,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }

    let res = new Response(response.body, response);

    const location = res.headers.get('Location');
    if (location) {
      try {
        const loc = new URL(location, targetUrl.origin);
        const locHost = loc.hostname.replace(/^www\./i, '');
        if (locHost === baseHost) {
          loc.protocol = 'http:';
          loc.hostname = origHostname;
          loc.port = origPort;
          res.headers.set('Location', loc.toString());
        }
      } catch {
        res.headers.set('Location', location.replace(new RegExp(`https?://(?:www\\.)?${escapedHost}(?::\\d+)?(?=[/?#]|$)`, 'gi'), `http://${originalHost}`));
      }
    }

    res.headers.delete('Strict-Transport-Security');
    res.headers.delete('Content-Security-Policy');
    res.headers.delete('Content-Security-Policy-Report-Only');

    const rawCookies = res.headers.getSetCookie();
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
    const mime = ct.split(';')[0].trim().toLowerCase();
    const isMarkup = /(?:html|xml|wml)$/.test(mime);
    if (request.method !== 'HEAD' && ![101, 204, 205, 304].includes(res.status) && TEXT_MIME.test(mime)) {
      const arrayBuf = await res.arrayBuffer();

      let charset = ct.match(/charset\s*=\s*["']?([^;"'\s]+)/i)?.[1]?.toLowerCase();
      if (!charset && isMarkup) {
        const preview = new TextDecoder('latin1').decode(arrayBuf.slice(0, 4096));
        const match = preview.match(/<meta[^>]+charset\s*=\s*["']?([a-zA-Z0-9_-]+)/i) ||
                      preview.match(/<\?xml[^>]+encoding\s*=\s*["']([a-zA-Z0-9_-]+)["']/i);
        if (match) charset = match[1].toLowerCase();
      }
      charset = charset || 'utf-8';

      let text;
      try {
        text = new TextDecoder(charset).decode(arrayBuf);
      } catch {
        text = new TextDecoder('utf-8').decode(arrayBuf);
      }

      const hostPattern = `(?:www\\.)?${escapedHost}`;
      const portPattern = targetPort ? `(?::${targetPort})?` : '(?::\\d+)?';
      const domainRegex = new RegExp(`(?:https?:(\\\\/\\\\/|//)|(?<![:a-zA-Z0-9+.-])(\\\\/\\\\/|//))${hostPattern}${portPattern}(?=[/?#"')\\\\\\s<>]|$)`, 'gi');
      text = text.replace(domainRegex, (_, s1, s2) => `http:${s1 || s2}${originalHost}`);

      if (isMarkup) {
        text = text
          .replace(/<meta[^>]*http-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*>/gi, '')
          .replace(/(<meta[^>]+charset\s*=\s*["']?)[a-zA-Z0-9_-]+(["']?)/gi, '$1utf-8$2')
          .replace(/(<\?xml[^>]+encoding\s*=\s*["'])[a-zA-Z0-9_-]+(["'])/gi, '$1utf-8$2');
      }

      const encoded = new TextEncoder().encode(text);
      const h = new Headers(res.headers);
      if (clientAE.includes('gzip')) {
        h.set('content-encoding', 'gzip');
      } else {
        h.delete('content-encoding');
      }
      h.set('content-type', /charset\s*=/i.test(ct) ? ct.replace(/charset\s*=\s*["']?[^;"'\s]+["']?/i, 'charset=utf-8') : `${ct}; charset=utf-8`);

      res = new Response(encoded, { status: res.status, statusText: res.statusText, headers: h });
    }

    res.headers.set('Access-Control-Allow-Origin', '*');
    res.headers.set('Access-Control-Allow-Methods', '*');
    res.headers.set('Access-Control-Allow-Headers', '*');

    return res;
  }
};
