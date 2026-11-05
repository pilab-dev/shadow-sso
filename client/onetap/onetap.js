// ShadowSSO One Tap client. Embed in your page to silently sign in users
// who already have an OP session, using the /oauth2/silent-authorize endpoint.
(function (global) {
  'use strict';
  function oneTap(opts) {
    opts = opts || {};
    var origin = opts.origin || window.location.origin;
    var iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = (opts.issuer || '') + '/oauth2/silent-authorize?client_id=' +
      encodeURIComponent(opts.clientId || '') + '&redirect_uri=' + encodeURIComponent(origin) +
      '&scope=' + encodeURIComponent(opts.scope || 'openid profile email') +
      '&response_type=' + encodeURIComponent(opts.responseType || 'code') +
      '&parent_origin=' + encodeURIComponent(origin);
    var handler = function (e) {
      if (e.origin !== new URL(opts.issuer || window.location.origin).origin) return;
      if (!e.data || e.data.type !== 'shadow-sso-silent') return;
      window.removeEventListener('message', handler);
      document.body.removeChild(iframe);
      if (typeof opts.onResult === 'function') opts.onResult(e.data);
    };
    window.addEventListener('message', handler);
    document.body.appendChild(iframe);
  }
  global.ShadowSSOOneTap = { oneTap: oneTap };
})(typeof window !== 'undefined' ? window : this);