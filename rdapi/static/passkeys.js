// Passkeys und Sicherheitsschlüssel (WebAuthn): Optionen vom Server holen, den Browser
// fragen, Antwort zurückschicken. Ohne WebAuthn im Browser bleiben die Knöpfe versteckt.
(() => {
  if (!window.PublicKeyCredential || !navigator.credentials) return;

  const toBuf = (s) => {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
  };
  const toB64 = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const creationOptions = (o) => ({
    ...o,
    challenge: toBuf(o.challenge),
    user: { ...o.user, id: toBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: toBuf(c.id) })),
  });
  const requestOptions = (o) => ({
    ...o,
    challenge: toBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: toBuf(c.id) })),
  });

  const credentialJSON = (cred) => {
    const r = cred.response;
    const response = { clientDataJSON: toB64(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = toB64(r.attestationObject);
      if (r.getTransports) response.transports = r.getTransports();
    } else {
      response.authenticatorData = toB64(r.authenticatorData);
      response.signature = toB64(r.signature);
      if (r.userHandle) response.userHandle = toB64(r.userHandle);
    }
    return {
      id: cred.id,
      rawId: toB64(cred.rawId),
      type: cred.type,
      response,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
    };
  };

  const post = (url, body) =>
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });

  // Ergebnis anzeigen: Weiterleitung folgen, eine ganze Seite übernehmen oder Fehler zeigen.
  const finish = async (resp, errorBox) => {
    if (resp.redirected) {
      window.location.assign(resp.url);
      return;
    }
    const type = resp.headers.get("content-type") || "";
    if (resp.ok && type.includes("text/html")) {
      document.open();
      document.write(await resp.text());
      document.close();
      return;
    }
    let message = errorBox.dataset.fallback;
    try {
      message = (await resp.json()).error || message;
    } catch (_) { /* keine JSON-Antwort */ }
    errorBox.textContent = message;
    errorBox.hidden = false;
  };

  const run = async (button, optionsUrl, optionsBody, submitUrl, submitBody, create) => {
    const errorBox = document.querySelector("[data-passkey-error]");
    errorBox.hidden = true;
    button.disabled = true;
    try {
      const resp = await post(optionsUrl, optionsBody);
      if (!resp.ok) return finish(resp, errorBox);
      const { token, options } = await resp.json();
      const cred = create
        ? await navigator.credentials.create({ publicKey: creationOptions(options) })
        : await navigator.credentials.get({ publicKey: requestOptions(options) });
      await finish(await post(submitUrl, { ...submitBody(), token, credential: credentialJSON(cred) }), errorBox);
    } catch (err) {
      // Abgebrochen oder nicht möglich: kurze Meldung statt technischem Fehler
      errorBox.textContent = errorBox.dataset.cancelled;
      errorBox.hidden = false;
    } finally {
      button.disabled = false;
    }
  };

  document.querySelectorAll("[data-passkey-login]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", () =>
      run(button, "/login/passkey/options", {}, "/login/passkey", () => ({ next: button.dataset.next }), false));
  });

  document.querySelectorAll("[data-passkey-second]").forEach((button) => {
    button.hidden = false;
    const pending = button.dataset.pending;
    button.addEventListener("click", () =>
      run(button, "/login/code/passkey/options", { pending }, "/login/code/passkey",
        () => ({ pending, next: button.dataset.next }), false));
  });

  document.querySelectorAll("form[data-passkey-register]").forEach((form) => {
    form.hidden = false;
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const csrf = form.elements.csrf.value;
      run(form.querySelector("button"), "/account/passkeys/options", { csrf }, "/account/passkeys",
        () => ({ csrf, name: form.elements.name.value }), true);
    });
  });
  document.querySelectorAll("[data-passkey-unsupported]").forEach((el) => { el.hidden = true; });
})();
