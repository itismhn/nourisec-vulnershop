// NouriSec VulnerShop - client-side glue code.

// VULN: Sensitive Data Exposure (WSTG-CRYP-04 / OWASP A02:2021) - a "payment
// gateway" secret accidentally left in client-side source. Anyone viewing
// this file (or the page source) can read it.
// TODO: remove before prod - PAYMENT_GATEWAY_API_KEY = "sk_test_51NouriSecFAKEKEYDONOTUSE7890"

document.addEventListener("DOMContentLoaded", function () {
    console.log("VulnerShop loaded - training lab build.");
});
