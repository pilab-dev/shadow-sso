// Passkey (WebAuthn) browser glue. Served from the SSO origin (CSP: script-src 'self').
// Buttons carry data-passkey="register|login" and data-csrf="<token>".
(function () {
  "use strict";

  function supported() {
    return !!(window.PublicKeyCredential &&
      PublicKeyCredential.parseCreationOptionsFromJSON &&
      PublicKeyCredential.parseRequestOptionsFromJSON);
  }

  function showError(msg) {
    var el = document.getElementById("passkey-error");
    if (el) { el.textContent = msg; el.hidden = false; }
  }

  async function post(url, csrf, body, json) {
    var headers = { "X-CSRF-Token": csrf };
    var init = { method: "POST", headers: headers, credentials: "same-origin" };
    if (json) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
    else { headers["Content-Type"] = "application/x-www-form-urlencoded"; init.body = new URLSearchParams(body || {}).toString(); }
    var res = await fetch(url, init);
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) { throw new Error(data.error || "Request failed."); }
    return data;
  }

  async function register(csrf) {
    var pw = document.getElementById("passkey-password");
    var name = document.getElementById("passkey-name");
    var options = await post("/account/passkeys/register/begin", csrf,
      { current_password: pw ? pw.value : "", name: name ? name.value : "" }, false);
    var cred = await navigator.credentials.create({
      publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey)
    });
    await post("/account/passkeys/register/finish", csrf, cred.toJSON(), true);
    window.location.href = "/account/passkeys?ok=passkey_added";
  }

  async function login(csrf) {
    var options = await post("/login/passkey/begin", csrf, {}, false);
    var cred = await navigator.credentials.get({
      publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey)
    });
    var result = await post("/login/passkey/finish", csrf, cred.toJSON(), true);
    window.location.href = result.next;
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-passkey]");
    if (!btn) { return; }
    e.preventDefault();
    if (!supported()) { showError("This browser does not support passkeys."); return; }
    var err = document.getElementById("passkey-error");
    if (err) { err.hidden = true; }
    btn.disabled = true;
    var action = btn.getAttribute("data-passkey") === "register" ? register : login;
    action(btn.getAttribute("data-csrf")).catch(function (ex) {
      if (ex && ex.name === "NotAllowedError") { showError("The passkey request was cancelled."); }
      else { showError(ex && ex.message ? ex.message : "Passkey request failed."); }
    }).finally(function () { btn.disabled = false; });
  });
})();
