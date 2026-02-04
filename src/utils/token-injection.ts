/**
 * Token Injection Utility
 *
 * Patches the webchat UI (served by clawdbot gateway) to properly include
 * the gateway token in WebSocket connections.
 *
 * Problem: The clawdbot webchat UI opens WebSocket connections without
 * including the ?token= query parameter, causing 1008 "Invalid or missing token" errors.
 *
 * Solution: Inject a script into HTML responses that:
 * 1. Captures the token from URL query params
 * 2. Stores it in sessionStorage for persistence across navigations
 * 3. Patches the WebSocket constructor to auto-add the token
 */

/**
 * Generate the token injection script to be inserted into HTML pages.
 * This script runs before any other scripts and patches WebSocket.
 */
export function getTokenInjectionScript(): string {
  return `<script data-token-patch="1">
(function() {
  'use strict';

  // === Token Extraction ===
  // Priority: URL param > sessionStorage > localStorage

  function getToken() {
    // 1. Check URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const urlToken = urlParams.get('token');
    if (urlToken && urlToken.length >= 32) {
      return urlToken;
    }

    // 2. Check sessionStorage (persists across navigations in same tab)
    try {
      const sessionToken = sessionStorage.getItem('moltbot_gateway_token');
      if (sessionToken && sessionToken.length >= 32) {
        return sessionToken;
      }
    } catch(e) {}

    // 3. Check localStorage (persists across sessions)
    try {
      const localToken = localStorage.getItem('moltbot_gateway_token');
      if (localToken && localToken.length >= 32) {
        return localToken;
      }
    } catch(e) {}

    return null;
  }

  function storeToken(token) {
    if (!token) return;
    try {
      sessionStorage.setItem('moltbot_gateway_token', token);
      localStorage.setItem('moltbot_gateway_token', token);
    } catch(e) {
      console.warn('[TokenPatch] Failed to store token:', e);
    }
  }

  // === Get and Store Token ===
  const gatewayToken = getToken();

  if (gatewayToken) {
    storeToken(gatewayToken);
    window.__MOLTBOT_GATEWAY_TOKEN__ = gatewayToken;
    console.log('[TokenPatch] Gateway token captured (length: ' + gatewayToken.length + ')');
  } else {
    console.warn('[TokenPatch] No gateway token found in URL or storage');
  }

  // === Patch WebSocket Constructor ===
  const OriginalWebSocket = window.WebSocket;

  function PatchedWebSocket(url, protocols) {
    // Get current token (may have been set after page load)
    const token = window.__MOLTBOT_GATEWAY_TOKEN__ || getToken();

    if (token) {
      try {
        const parsedUrl = new URL(url, window.location.origin);

        // Only patch WebSocket connections to same host
        if (parsedUrl.host === window.location.host) {
          // Add token if not already present
          if (!parsedUrl.searchParams.has('token')) {
            parsedUrl.searchParams.set('token', token);
            url = parsedUrl.toString();
            console.log('[TokenPatch] Added token to WebSocket URL');
          }
        }
      } catch(e) {
        console.warn('[TokenPatch] Failed to parse WebSocket URL:', e);
      }
    }

    console.log('[TokenPatch] WebSocket connecting to:', url.replace(/token=[^&]+/, 'token=[REDACTED]'));

    // Call original constructor
    if (protocols !== undefined) {
      return new OriginalWebSocket(url, protocols);
    } else {
      return new OriginalWebSocket(url);
    }
  }

  // Copy static properties and prototype
  PatchedWebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  PatchedWebSocket.OPEN = OriginalWebSocket.OPEN;
  PatchedWebSocket.CLOSING = OriginalWebSocket.CLOSING;
  PatchedWebSocket.CLOSED = OriginalWebSocket.CLOSED;

  // Inherit prototype for instanceof checks
  Object.setPrototypeOf(PatchedWebSocket, OriginalWebSocket);
  Object.setPrototypeOf(PatchedWebSocket.prototype, OriginalWebSocket.prototype);

  // Replace global WebSocket
  window.WebSocket = PatchedWebSocket;

  console.log('[TokenPatch] WebSocket constructor patched successfully');

  // === Handle Page Visibility (reconnection scenarios) ===
  // When tab becomes visible again, ensure token is still available
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      const token = getToken();
      if (token) {
        window.__MOLTBOT_GATEWAY_TOKEN__ = token;
      }
    }
  });

})();
</script>`;
}

/**
 * Check if an HTML response should have the token script injected.
 *
 * @param contentType - The Content-Type header value
 * @param pathname - The request pathname
 * @returns true if script should be injected
 */
export function shouldInjectTokenScript(contentType: string | null, pathname: string): boolean {
  // Only inject into HTML responses
  if (!contentType?.includes('text/html')) {
    return false;
  }

  // Don't inject into admin UI (it doesn't need WebSocket patching)
  if (pathname.startsWith('/_admin')) {
    return false;
  }

  // Don't inject into API responses
  if (pathname.startsWith('/api')) {
    return false;
  }

  // Don't inject into debug routes
  if (pathname.startsWith('/debug')) {
    return false;
  }

  return true;
}

/**
 * Inject the token script into an HTML string.
 * Inserts the script as early as possible in the <head> so it runs
 * before any other scripts that might create WebSocket connections.
 *
 * @param html - The HTML content to modify
 * @returns Modified HTML with injected script
 */
export function injectTokenScript(html: string): string {
  const script = getTokenInjectionScript();

  // Check if already injected (idempotent)
  if (html.includes('data-token-patch="1"')) {
    return html;
  }

  // Priority 1: Inject right after <head> tag (before any other scripts)
  const headMatch = html.match(/<head[^>]*>/i);
  if (headMatch) {
    const headTag = headMatch[0];
    const headIndex = html.indexOf(headTag) + headTag.length;
    return html.slice(0, headIndex) + '\n' + script + '\n' + html.slice(headIndex);
  }

  // Priority 2: Inject before </head>
  if (html.includes('</head>')) {
    return html.replace('</head>', script + '\n</head>');
  }

  // Priority 3: Inject after <html> tag
  const htmlMatch = html.match(/<html[^>]*>/i);
  if (htmlMatch) {
    const htmlTag = htmlMatch[0];
    const htmlIndex = html.indexOf(htmlTag) + htmlTag.length;
    return html.slice(0, htmlIndex) + '\n' + script + '\n' + html.slice(htmlIndex);
  }

  // Priority 4: Inject at the very beginning
  return script + '\n' + html;
}

/**
 * Process an HTTP response, injecting token script if appropriate.
 *
 * @param response - The original Response from the container
 * @param pathname - The request pathname
 * @returns Modified Response with injected script, or original if not applicable
 */
export async function processResponseForTokenInjection(
  response: Response,
  pathname: string
): Promise<Response> {
  const contentType = response.headers.get('content-type');

  // Check if we should inject
  if (!shouldInjectTokenScript(contentType, pathname)) {
    return response;
  }

  // Read the HTML body
  const html = await response.text();

  // Inject the token script
  const modifiedHtml = injectTokenScript(html);

  // Create new response with modified HTML
  const newHeaders = new Headers(response.headers);
  newHeaders.set('X-Token-Patch', 'injected');

  // Update content-length if it was set
  if (newHeaders.has('content-length')) {
    newHeaders.set('content-length', String(new TextEncoder().encode(modifiedHtml).length));
  }

  return new Response(modifiedHtml, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
