// Closes the browser's FedCM login dialog after the IdP login completes.
// Served as an external file because the SSO CSP only allows scripts from 'self'.
(function () {
  function closeFedCMDialog() {
    try {
      if (window.IdentityProvider && typeof window.IdentityProvider.close === "function") {
        window.IdentityProvider.close();
        return true;
      }
    } catch (error) {
      // Ignore: the FedCM API may be unavailable outside the dialog.
    }
    return false;
  }

  if (!closeFedCMDialog()) {
    // Fallback for non-FedCM windows opened by the login page.
    try {
      window.close();
    } catch (error) {
      // Browsers may block window.close(); the page text tells the user what to do.
    }
  }
})();
